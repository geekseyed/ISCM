using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-03.4: Target Test Discovery Service.
/// Stage 3.4.1 No hard-coded path: the solution path is a MANDATORY
///          input; the service invents no default target.
/// Stage 3.4.2 Resolve configured test projects: an explicit test-project
///          list is AUTHORITATIVE when provided (each entry validated to
///          exist on disk); entries absent from the solution inventory
///          remain valid targets + a diagnostic.
/// Stage 3.4.3 Solution inventory: structurally parses the .sln project
///          lines (type-guid/name/path/guid), keeps C# projects (classic
///          FAE04EC0 / SDK-style 9A19103F), skips solution folders.
/// Stage 3.4.4 Multiple test assemblies: any number of test targets.
/// Stage 3.4.5 Preserve target identity: name/path/guid/type-guid plus
///          the per-target DetectionReason.
///
/// v1 DETECTION HEURISTIC (documented, not hidden): without an explicit
/// list, a project is a test project when its name ends with ".Tests".
/// The heuristic is recorded verbatim in DetectionReason; csproj-level
/// IsTestProject parsing is a documented H-03.6+ refinement.
/// </summary>
public class TestTargetDiscoveryService
{
    private static readonly Regex ProjectLinePattern = new(
        "^Project\\(\"(?<type>[^\"]+)\"\\)\\s*=\\s*\"(?<name>[^\"]*)\",\\s*\"(?<path>[^\"]*)\",\\s*\"(?<guid>[^\"]+)\"",
        RegexOptions.Compiled);

    private const string CSharpClassicTypeGuid = "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC";
    private const string CSharpSdkTypeGuid = "9A19103F-16F7-4668-BE54-9A1E7A4F7556";
    private const string SolutionFolderTypeGuid = "2150E333-8FDC-42A3-9474-1A3956D46DE8";

    private const string TestsSuffix = ".Tests";

    /// <summary>
    /// Discover test targets. explicitTestProjectPaths (3.4.2) is
    /// authoritative when provided; otherwise the name-convention
    /// heuristic (documented) decides.
    /// </summary>
    public TestTargetDiscoveryReport Discover(
    string solutionPath,
    IReadOnlyList<string>? explicitTestProjectPaths = null)
    {
        if (string.IsNullOrWhiteSpace(solutionPath))
            throw new ArgumentException(
                "Solution path is required - no default target is invented " +
                "(audit KBF-01-004).", nameof(solutionPath));
        if (!File.Exists(solutionPath))
            throw new ArgumentException(
                $"Solution file not found: '{solutionPath}'.", nameof(solutionPath));

        var fullSolutionPath = Path.GetFullPath(solutionPath);
        var solutionDirectory = Path.GetDirectoryName(fullSolutionPath)!;
        var diagnostics = new List<string>();

        // Stage 3.4.3 — structural .sln inventory
        var inventory = ParseSolutionInventory(
            File.ReadAllLines(fullSolutionPath), diagnostics);

        // Stage 3.4.2 — explicit configuration is authoritative
        var explicitTargets = new List<TestTarget>();
        if (explicitTestProjectPaths is { Count: > 0 })
        {
            foreach (var rawPath in explicitTestProjectPaths)
            {
                if (string.IsNullOrWhiteSpace(rawPath))
                    throw new ArgumentException(
                        "Explicit test project list contains an empty path.",
                        nameof(explicitTestProjectPaths));

                var fullProjectPath = Path.GetFullPath(
                    Path.IsPathRooted(rawPath) ? rawPath : Path.Combine(solutionDirectory, rawPath));

                if (!File.Exists(fullProjectPath))
                    throw new ArgumentException(
                        $"Configured test project not found on disk: '{fullProjectPath}'.",
                        nameof(explicitTestProjectPaths));

                var relative = Path.IsPathRooted(rawPath)
                    ? rawPath
                    : rawPath.Replace('\\', '/');

                var matchedInventory = inventory.FirstOrDefault(p =>
                    string.Equals(
                        JoinSolutionPath(solutionDirectory, p.ProjectFilePath),
                        fullProjectPath, StringComparison.OrdinalIgnoreCase));

                if (matchedInventory is null)
                    diagnostics.Add(
                        $"explicit test project '{relative}' is not part of the " +
                        "solution inventory (still a valid standalone target)");

                explicitTargets.Add(new TestTarget
                {
                    ProjectName = matchedInventory?.ProjectName
                                  ?? Path.GetFileNameWithoutExtension(fullProjectPath),
                    ProjectFilePath = relative,
                    ProjectGuid = matchedInventory?.ProjectGuid ?? string.Empty,
                    ProjectTypeGuid = matchedInventory?.ProjectTypeGuid ?? string.Empty,
                    IsTestProject = true,
                    DetectionReason = TestTargetDetectionReason.ExplicitConfiguration
                });
            }

            diagnostics.Insert(0,
                "explicit test-project configuration is authoritative " +
                $"({explicitTargets.Count} target(s)); name-convention detection bypassed");
        }

        // Detection per inventory project (when no explicit configuration)
        var allProjects = inventory
            .OrderBy(p => p.ProjectFilePath, StringComparer.Ordinal)
            .ToList();

        IReadOnlyList<TestTarget> testProjects;
        if (explicitTargets.Count > 0)
        {
            testProjects = explicitTargets
                .OrderBy(t => t.ProjectFilePath, StringComparer.Ordinal)
                .ToList();
        }
        else
        {
            testProjects = allProjects
                .Where(p => IsTestByNameConvention(p.ProjectName))
                .Select(p => new TestTarget
                {
                    ProjectName = p.ProjectName,
                    ProjectFilePath = p.ProjectFilePath,
                    ProjectGuid = p.ProjectGuid,
                    ProjectTypeGuid = p.ProjectTypeGuid,
                    IsTestProject = true,
                    DetectionReason = TestTargetDetectionReason.NameConvention
                })
                .OrderBy(t => t.ProjectFilePath, StringComparer.Ordinal)
                .ToList();

            if (testProjects.Count == 0)
                diagnostics.Add("no test projects detected in the solution inventory");
        }

        return new TestTargetDiscoveryReport
        {
            SolutionPath = fullSolutionPath,
            AllProjects = allProjects,
            TestProjects = testProjects,
            TotalProjectCount = allProjects.Count,
            TestProjectCount = testProjects.Count,
            Diagnostics = diagnostics
        };
    }

    // ---------- internals ----------

    private static bool IsTestByNameConvention(string projectName) =>
        projectName.EndsWith(TestsSuffix, StringComparison.OrdinalIgnoreCase)
        || projectName.Contains(TestsSuffix + ".", StringComparison.OrdinalIgnoreCase);

    private static string JoinSolutionPath(string solutionDirectory, string relativeProjectPath) =>
        Path.GetFullPath(Path.Combine(solutionDirectory, relativeProjectPath));

    private List<TestTarget> ParseSolutionInventory(
        string[] lines, List<string> diagnostics)
    {
        var targets = new List<TestTarget>();
        var skippedNonCSharp = 0;

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();
            if (!trimmed.StartsWith("Project(", StringComparison.Ordinal))
                continue;

            var match = ProjectLinePattern.Match(trimmed);
            if (!match.Success)
            {
                diagnostics.Add($"malformed Project line skipped: '{trimmed}'");
                continue;
            }

            var typeGuid = match.Groups["type"].Value.Trim().Trim('{', '}');
            if (string.Equals(typeGuid, SolutionFolderTypeGuid, StringComparison.OrdinalIgnoreCase))
            {
                skippedNonCSharp++;   // solution folders are not projects
                continue;
            }

            if (!string.Equals(typeGuid, CSharpClassicTypeGuid, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(typeGuid, CSharpSdkTypeGuid, StringComparison.OrdinalIgnoreCase))
            {
                skippedNonCSharp++;
                continue;
            }

            targets.Add(new TestTarget
            {
                ProjectName = match.Groups["name"].Value,
                ProjectFilePath = match.Groups["path"].Value.Replace('\\', '/'),
                ProjectGuid = match.Groups["guid"].Value.Trim().Trim('{', '}'),
                ProjectTypeGuid = typeGuid,
                IsTestProject = false,   // detection pass decides below
                DetectionReason = TestTargetDetectionReason.NotDetected
            });
        }

        if (skippedNonCSharp > 0)
            diagnostics.Add($"{skippedNonCSharp} non-C# solution entries skipped");

        return targets;
    }
}