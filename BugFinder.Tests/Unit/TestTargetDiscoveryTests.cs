using System;
using System.IO;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class TestTargetDiscoveryTests : IDisposable
{
    private readonly TestTargetDiscoveryService _service = new();

    private const string CSharpClassic = "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC";
    private const string CSharpSdk = "9A19103F-16F7-4668-BE54-9A1E7A4F7556";
    private const string SolutionFolder = "2150E333-8FDC-42A3-9474-1A3956D46DE8";

    private string? _tempDirectory;

    /// <summary>
    /// Write a real .sln to a temp dir (the sln line format is the REAL
    /// VS format: Project("{TypeGuid}") = "Name", "Path", "{ProjectGuid}")
    /// and optionally create the referenced project files on disk.
    /// </summary>
    private string WriteSolution(
        params (string TypeGuid, string Name, string Path, string ProjectGuid)[] projects)
        => WriteSolution(projects, createProjectFiles: false);

    private string WriteSolution(
        (string TypeGuid, string Name, string Path, string ProjectGuid)[] projects,
        bool createProjectFiles)
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"sln-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDirectory);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Microsoft Visual Studio Solution File, Format Version 12.00");

        foreach (var (typeGuid, name, path, projectGuid) in projects)
        {
            sb.AppendLine($"Project(\"{{{typeGuid}}}\") = \"{name}\", \"{path}\", \"{{{projectGuid}}}\"");
            sb.AppendLine("EndProject");

            if (createProjectFiles)
            {
                var fullPath = Path.Combine(_tempDirectory, path.Replace('/', '\\'));
                Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
                File.WriteAllText(fullPath, "<Project/>");
            }
        }

        var slnPath = Path.Combine(_tempDirectory, "Probe.sln");
        File.WriteAllText(slnPath, sb.ToString());
        return slnPath;
    }

    private (string SlnPath, string Dir) WriteSolutionWithFiles(
        params (string TypeGuid, string Name, string Path, string ProjectGuid)[] projects)
    {
        var slnPath = WriteSolution(projects, createProjectFiles: true);
        return (slnPath, _tempDirectory!);
    }

    public void Dispose()
    {
        try { if (_tempDirectory != null) Directory.Delete(_tempDirectory, recursive: true); }
        catch { /* best effort cleanup */ }
    }

    // Stage 3.4.3 — structural sln parse preserves identity (3.4.5)
    [Fact]
    public void Discover_ParsesSolution_PreservesTargetIdentity()
    {
        var sln = WriteSolution(
            (CSharpClassic, "ISCM.Domain", @"ISCM.Domain\ISCM.Domain.csproj", "11111111-1111-1111-1111-111111111111"),
            (CSharpSdk, "ISCM.Tests", @"ISCM.Tests\ISCM.Tests.csproj", "22222222-2222-2222-2222-222222222222"));

        var report = _service.Discover(sln);

        report.TotalProjectCount.Should().Be(2);
        report.AllProjects.Select(p => p.ProjectName)
            .Should().ContainInOrder("ISCM.Domain", "ISCM.Tests");

        var tests = report.TestProjects.Single();
        tests.ProjectName.Should().Be("ISCM.Tests");
        tests.ProjectFilePath.Should().Be("ISCM.Tests/ISCM.Tests.csproj");   // slash-normalized
        tests.ProjectGuid.Should().Be("22222222-2222-2222-2222-222222222222");
        tests.ProjectTypeGuid.Should().Be(CSharpSdk);
        tests.DetectionReason.Should().Contain("name convention");
    }

    // Solution folders are not projects
    [Fact]
    public void Discover_SolutionFolders_Skipped()
    {
        var sln = WriteSolution(
            (SolutionFolder, "Solution Items", $"Solution Items\\{Guid.NewGuid():N}.slnitems", "33333333-3333-3333-3333-333333333333"),
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));

        var report = _service.Discover(sln);

        report.TotalProjectCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("non-C#"));
    }

    // Stage 3.4.2 — explicit configuration is authoritative
    [Fact]
    public void Discover_ExplicitConfiguration_Wins_AndIsAuthoritative()
    {
        var (sln, dir) = WriteSolutionWithFiles(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"),
            (CSharpSdk, "ISCM.Tests", @"ISCM.Tests\ISCM.Tests.csproj", "22222222-2222-2222-2222-222222222222"));

        var report = _service.Discover(sln, new[] { @"ISCM.Tests\ISCM.Tests.csproj" });

        report.TestProjects.Should().ContainSingle();
        report.TestProjects[0].DetectionReason.Should().Contain("explicit configuration");
        report.Diagnostics[0].Should().Contain("authoritative");
    }

    // Stage 3.4.2 — explicit entry not present in the sln: still a valid
    // standalone target + diagnostic (no silent drop)
    [Fact]
    public void Discover_ExplicitEntryNotInSolution_ValidTargetPlusDiagnostic()
    {
        var (sln, dir) = WriteSolutionWithFiles(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));
        var standalone = Path.Combine(dir, "Standalone.Tests.csproj");
        File.WriteAllText(standalone, "<Project/>");

        var report = _service.Discover(sln, new[] { "Standalone.Tests.csproj" });

        report.TestProjects.Should().ContainSingle(t =>
            t.ProjectFilePath == "Standalone.Tests.csproj"
            && t.DetectionReason.Contains("explicit configuration"));
        report.Diagnostics.Should().Contain(d => d.Contains("not part of the solution inventory"));
    }

    // Explicit entries must exist on disk (fail-fast configuration error)
    [Fact]
    public void Discover_ExplicitEntryMissingOnDisk_Throws()
    {
        var sln = WriteSolution(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));

        Action act = () => _service.Discover(sln, new[] { "Missing\\Nope.csproj" });
        act.Should().Throw<ArgumentException>().WithMessage("*not found on disk*");
    }

    // Stage 3.4.4 — multiple test assemblies
    [Fact]
    public void Discover_MultipleTestAssemblies_Supported()
    {
        var sln = WriteSolution(
            (CSharpSdk, "ISCM.Tests", @"ISCM.Tests\ISCM.Tests.csproj", "22222222-2222-2222-2222-222222222222"),
            (CSharpSdk, "ISCM.BugFinder.Tests", @"BugFinder.Tests\BugFinder.Tests.csproj", "55555555-5555-5555-5555-555555555555"));

        var report = _service.Discover(sln);

        report.TestProjects.Should().HaveCount(2);
        report.TestProjectCount.Should().Be(2);
    }

    // No test projects → explicit diagnostic (never a fabricated target)
    [Fact]
    public void Discover_NoTestProjects_DiagnosticEmitted()
    {
        var sln = WriteSolution(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));

        var report = _service.Discover(sln);

        report.TestProjects.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d => d.Contains("no test projects detected"));
    }

    // Malformed Project lines are skipped with a diagnostic
    [Fact]
    public void Discover_MalformedProjectLines_SkippedWithDiagnostic()
    {
        var slnPath = WriteSolution(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));

        // inject a malformed Project line into the REAL sln file
        var lines = File.ReadAllLines(slnPath).ToList();
        lines.Insert(1, "Project(\"broken-line");
        File.WriteAllLines(slnPath, lines);

        var report = _service.Discover(slnPath);

        report.TotalProjectCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("malformed Project line"));
    }

    // Contract: missing sln / empty path fail fast (no invented defaults)
    [Fact]
    public void Discover_MissingSolutionFile_Throws()
    {
        Action act = () => _service.Discover(
            Path.Combine(Path.GetTempPath(), "missing-h03z9.sln"));
        act.Should().Throw<ArgumentException>().WithMessage("*not found*");
    }

    [Fact]
    public void Discover_EmptySolutionPath_Throws()
    {
        Action act = () => _service.Discover("  ");
        act.Should().Throw<ArgumentException>().WithMessage("*no default target*");
    }

    [Fact]
    public void Discover_NullExplicitEntry_Throws()
    {
        var sln = WriteSolution(
            (CSharpClassic, "App", @"App\App.csproj", "44444444-4444-4444-4444-444444444444"));

        Action act = () => _service.Discover(sln, new string[] { null! });
        act.Should().Throw<ArgumentException>();
    }

    // v1 heuristic documented: name-contains-.Tests also matches
    [Fact]
    public void Discover_NameConvention_Variant_Matches()
    {
        var sln = WriteSolution(
            (CSharpSdk, "ISCM.Tests.Unit", @"Tests.Unit\Tests.Unit.csproj", "66666666-6666-6666-6666-666666666666"));

        var report = _service.Discover(sln);

        report.TestProjects.Should().ContainSingle();
        report.TestProjects[0].DetectionReason.Should().Contain("heuristic");
    }
}