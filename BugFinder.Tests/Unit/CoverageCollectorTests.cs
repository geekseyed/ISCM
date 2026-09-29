using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CoverageCollectorTests : IDisposable
{
    private readonly CoverageCollectorService _service = new();
    private readonly string _tempDirectory;

    public CoverageCollectorTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"cov-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private CoverageCollectionInput Input(
        string? project = @"tests\X.csproj", string? resultsDir = null) => new()
        {
            WorkingDirectory = _tempDirectory,
            TestProjectPath = project ?? string.Empty,
            ResultsDirectory = resultsDir ?? Path.Combine(_tempDirectory, "results")
        };

    // ---------- Stage 4.1.2 — structured arguments ----------

    [Fact]
    public void BuildCoverageArguments_ContainsCollectorAndResultsDir()
    {
        var args = _service.BuildCoverageArguments(@"tests\X.csproj", @"results\cov");

        args.Should().Contain("test");
        args.Should().Contain(@"tests\X.csproj");
        args.Should().Contain("--collect");
        args.Should().Contain("XPlat Code Coverage");
        args.Should().Contain("--results-directory");
        args.Should().Contain(@"results\cov");
    }

    // KBF-01-004 continuity — no default target invented
    [Fact]
    public void BuildCoverageArguments_EmptyProjectPath_Throws()
    {
        Action act = () => _service.BuildCoverageArguments("  ", @"results\cov");
        act.Should().Throw<ArgumentException>().WithMessage("*no default target*");
    }

    [Fact]
    public void BuildCoverageArguments_EmptyResultsDirectory_Throws()
    {
        Action act = () => _service.BuildCoverageArguments("x.csproj", " ");
        act.Should().Throw<ArgumentException>();
    }

    // H-04.1.1 — authoritative collector documented
    [Fact]
    public void AuthoritativeCollector_IsCoverletXPlat()
    {
        CoverageCollectorService.AuthoritativeCollector.Should().Contain("XPlat Code Coverage");
    }

    // ---------- Stage 4.1.4 — artifact discovery ----------

    [Fact]
    public void FindCoverageArtifact_NonExistentDirectory_ReturnsNull()
    {
        _service.FindCoverageArtifact(
            Path.Combine(_tempDirectory, "no-such-dir")).Should().BeNull();
    }

    [Fact]
    public void FindCoverageArtifact_CoberturaInGuidSubDirectory_Found()
    {
        var resultsDir = Path.Combine(_tempDirectory, "results");
        var guidSubDir = Path.Combine(resultsDir, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(guidSubDir);
        var artifact = Path.Combine(guidSubDir, "coverage.cobertura.xml");
        File.WriteAllText(artifact, "<?xml version=\"1.0\"?><Coverage />");

        _service.FindCoverageArtifact(resultsDir).Should().Be(artifact);
    }

    [Fact]
    public void FindCoverageArtifact_MultipleCandidates_NewestByWriteTime()
    {
        var resultsDir = Path.Combine(_tempDirectory, "results");
        var sub1 = Path.Combine(resultsDir, "run-1");
        var sub2 = Path.Combine(resultsDir, "run-2");
        Directory.CreateDirectory(sub1);
        Directory.CreateDirectory(sub2);

        var older = Path.Combine(sub1, "coverage.cobertura.xml");
        var newer = Path.Combine(sub2, "coverage.cobertura.xml");
        File.WriteAllText(older, "<x/>");
        File.WriteAllText(newer, "<x/>");
        File.SetLastWriteTimeUtc(older, DateTimeOffset.UtcNow.AddDays(-1).UtcDateTime);

        _service.FindCoverageArtifact(resultsDir).Should().Be(newer);
    }

    [Fact]
    public void FindCoverageArtifact_NoCoverageFiles_ReturnsNull()
    {
        var resultsDir = Path.Combine(_tempDirectory, "empty-results");
        Directory.CreateDirectory(resultsDir);
        File.WriteAllText(Path.Combine(resultsDir, "other.txt"), "x");

        _service.FindCoverageArtifact(resultsDir).Should().BeNull();
    }

    // ---------- CollectAsync — composition ----------

    // Stage 4.1.6 — process ran, no artifact => NotCollected (honest)
    [Fact]
    public async Task CollectAsync_ProcessCompleted_NoArtifact_NotCollected()
    {
        var resultsDir = Path.Combine(_tempDirectory, "results-empty");
        var input = Input(resultsDir: resultsDir);

        var result = await _service.CollectAsync(input);

        // the collection attempt completed with process truth
        result.Kind.Should().Be(ServiceResultKind.Success);
        result.Value!.Status.Should().Be(CoverageCollectionStatus.NotCollected);
        result.Value.ArtifactExists.Should().BeFalse();
        result.Value.ArtifactPath.Should().BeNull();
        result.Value.TerminatedByCancellation.Should().BeFalse();
    }

    // THE KBF-06 semantic seed: pre-placed artifact => Collected
    // (full CollectAsync path: real process launch + artifact resolution)
    // TestsFailed is NULL (Unknown) from exit code alone — the authoritative
    // value comes from TRX parsing (H-03.5).
    [Fact]
    public async Task CollectAsync_PrePlacedArtifact_Collected()
    {
        var resultsDir = Path.Combine(_tempDirectory, "results-with-artifact");
        var guidSubDir = Path.Combine(resultsDir, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(guidSubDir);
        var artifact = Path.Combine(guidSubDir, "coverage.cobertura.xml");
        File.WriteAllText(artifact, "<?xml version=\"1.0\"?><Coverage />");

        var result = await _service.CollectAsync(Input(resultsDir: resultsDir));

        result.Kind.Should().Be(ServiceResultKind.Success);
        var evidence = result.Value!;
        evidence.Status.Should().Be(CoverageCollectionStatus.Collected);
        evidence.ArtifactExists.Should().BeTrue();
        evidence.ArtifactPath.Should().Be(artifact);
        evidence.ArtifactSizeBytes.Should().BeGreaterThan(0);
        evidence.ProcessId.Should().NotBeNull();           // H-03.1 continuity
        evidence.TestsFailed.Should().BeNull();            // honest: ambiguous from exit code
    }

    // THE KBF-06 semantic seed: tests failing does NOT invalidate coverage
    [Fact]
    public async Task CollectAsync_TestsFailed_CoverageStillCollected()
    {
        var resultsDir = Path.Combine(_tempDirectory, "results-failed-tests");
        var guidSubDir = Path.Combine(resultsDir, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(guidSubDir);
        File.WriteAllText(Path.Combine(guidSubDir, "coverage.cobertura.xml"), "<Coverage />");

        var result = await _service.CollectAsync(Input(resultsDir: resultsDir));

        result.Kind.Should().Be(ServiceResultKind.Success);
        result.Value!.Status.Should().Be(CoverageCollectionStatus.Collected);
        result.Value!.TestsFailed.Should().BeNull();
    }

    // The pinned semantic: Status=Collected coexists with ANY test outcome —
    // and TestsFailed is NULL (Unknown) when derived from exit code alone,
    // because exit 1 is ambiguous (tests failed OR build failure). The
    // authoritative value comes from TRX parsing (H-03.5).
    [Fact]
    public void Semantic_TestsFailed_IsUnknownFromExitCode_CollectedStillValid()
    {
        var evidence = new CoverageCollectionEvidence
        {
            ExitCode = 1,
            Status = CoverageCollectionStatus.Collected,
            ArtifactExists = true,
            TestsFailed = null          // honest: indeterminate from exit code
        };

        evidence.Status.Should().Be(CoverageCollectionStatus.Collected); // coverage valid
        evidence.TestsFailed.Should().BeNull();                          // outcome unknown
    }

    // Stage 4.1.6 — cancelled BEFORE launch: Unavailable, nothing ran
    [Fact]
    public async Task CollectAsync_CancelledBeforeLaunch_Unavailable()
    {
        var input = Input();

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await _service.CollectAsync(input, cts.Token);

        result.Kind.Should().Be(ServiceResultKind.Unavailable);
        result.HasValue.Should().BeFalse();
    }

    // Contract violations fail fast (H-01.8 boundary)
    [Fact]
    public async Task CollectAsync_EmptyProjectPath_Throws()
    {
        var input = Input(project: "  ");
        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.CollectAsync(input));
    }

    [Fact]
    public async Task CollectAsync_InvalidWorkingDirectory_Throws()
    {
        var input = new CoverageCollectionInput
        {
            WorkingDirectory = @"Z:\definitely-missing-dir",
            TestProjectPath = "x.csproj",
            ResultsDirectory = Path.Combine(_tempDirectory, "r")
        };

        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.CollectAsync(input));
    }

    [Fact]
    public async Task CollectAsync_NullInput_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _service.CollectAsync(null!));
    }
}