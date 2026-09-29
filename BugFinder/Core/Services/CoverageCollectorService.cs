using System.Diagnostics;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.1: Coverage Collector Service.
/// Launches "dotnet test --collect:XPlat Code Coverage" through the
/// H-03.1 process infrastructure (real exit code, real timestamps, owned
/// child lifetime) and resolves the produced coverage artifact.
///
/// Stage 4.1.1  authoritative collector: coverlet XPlat Code Coverage
///              (already shipped by the repo's test projects).
/// Stage 4.1.2  structured arguments via ArgumentList (KBF-10-001 pattern).
/// Stage 4.1.3  collector exit status: the REAL process exit code —
///              exit 1 = tests failed, coverage still valid (KBF-06 seed).
/// Stage 4.1.4  artifact path: recursive scan of the results directory
///              for coverage.cobertura.xml (coverlet's layout:
///              results-dir/{guid}/coverage.cobertura.xml).
/// Stage 4.1.5  metadata: arguments audit copy + artifact size.
/// Stage 4.1.6  Collected vs NotCollected — explicit; a completed run
///              without an artifact is NotCollected, NEVER a fabricated
///              success (anti-KBF-01-001 pattern).
///
/// RESULT SHAPE (H-01.8): Success (process completed — Status field
/// carries Collected/NotCollected) / Unavailable (cancelled before or
/// during collection) / DiagnosticError (engine bug). Invalid inputs =
/// fail-fast ArgumentException (H-01.8 boundary).
/// </summary>
public class CoverageCollectorService
{
    public const string AuthoritativeCollector = "coverlet XPlat Code Coverage";

    private readonly ProcessExecutionService _process = new();

    /// <summary>Stage 4.1.2 — structured coverage arguments.</summary>
    public IReadOnlyList<string> BuildCoverageArguments(
        string testProjectPath, string resultsDirectory)
    {
        if (string.IsNullOrWhiteSpace(testProjectPath))
            throw new ArgumentException(
                "Test project path is required - no default target is invented " +
                "(KBF-01-004 continuity).", nameof(testProjectPath));
        if (string.IsNullOrWhiteSpace(resultsDirectory))
            throw new ArgumentException(
                "Results directory is required.", nameof(resultsDirectory));

        // structured list: ArgumentList quotes "XPlat Code Coverage" safely
        return new List<string>
        {
            "test",
            testProjectPath,
            "--collect",
            AuthoritativeCollector.Replace("coverlet ", string.Empty),   // "XPlat Code Coverage"
            "--results-directory",
            resultsDirectory,
            "--no-restore"
        };
    }

    /// <summary>
    /// Stage 4.1.4 — scan the results directory (recursively) for the
    /// coverlet artifact; newest by write time wins.
    /// </summary>
    public string? FindCoverageArtifact(string resultsDirectory)
    {
        if (string.IsNullOrWhiteSpace(resultsDirectory))
            throw new ArgumentException("Results directory is required.", nameof(resultsDirectory));
        if (!Directory.Exists(resultsDirectory))
            return null;

        return Directory
            .EnumerateFiles(resultsDirectory, "coverage.cobertura.xml", SearchOption.AllDirectories)
            .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
            .FirstOrDefault();
    }

    /// <summary>Full collection: launch + wait + resolve artifact.</summary>
    public async Task<ServiceResult<CoverageCollectionEvidence>> CollectAsync(
        CoverageCollectionInput input, CancellationToken cancellationToken = default)
    {
        try
        {
            if (input is null) throw new ArgumentNullException(nameof(input));

            var workingDirectory = ValidateWorkingDirectory(input.WorkingDirectory);
            var arguments = BuildCoverageArguments(
                input.TestProjectPath, input.ResultsDirectory);

            // ensure the results directory exists (scan target + coverlet output)
            Directory.CreateDirectory(Path.GetFullPath(input.ResultsDirectory));

            var launchInput = new ProcessLaunchInput
            {
                WorkingDirectory = workingDirectory,
                TestProjectPath = input.TestProjectPath,
                ResultArtifactPath = input.ResultsDirectory,
                Executable = input.Executable
            };

            var processResult = await _process.ExecuteRawAsync(launchInput, arguments, cancellationToken);

            // cancelled / launch failure — coverage never completed
            if (processResult.Kind == ServiceResultKind.Unavailable)
                return ServiceResult<CoverageCollectionEvidence>.Unavailable(
                    string.Join("; ", processResult.Reasons),
                    nameof(CoverageCollectorService));

            if (processResult.Kind == ServiceResultKind.DiagnosticError)
            {
                var diagnostic = processResult.Diagnostics.FirstOrDefault();
                return ServiceResult<CoverageCollectionEvidence>.DiagnosticError(
                    diagnostic?.Message ?? "process execution diagnostic error",
                    nameof(CoverageCollectorService));
            }

            // cancelled MID-RUN arrives as Partial — coverage incomplete
            if (processResult.Kind == ServiceResultKind.Partial)
                return ServiceResult<CoverageCollectionEvidence>.Unavailable(
                    "coverage collection cancelled before completion",
                    nameof(CoverageCollectorService));

            var processEvidence = processResult.Value!;

            // Stage 4.1.4 — resolve the artifact
            var artifactPath = FindCoverageArtifact(input.ResultsDirectory);
            var artifactExists = artifactPath is not null;
            long? artifactSize = artifactPath is not null
                ? new FileInfo(artifactPath).Length
                : null;

            var evidence = new CoverageCollectionEvidence
            {
                ProcessId = processEvidence.ProcessId,
                StartUtc = processEvidence.StartUtc,
                EndUtc = processEvidence.EndUtc,
                ExitCode = processEvidence.ExitCode,
                TerminatedByCancellation = processEvidence.TerminatedByCancellation,
                Arguments = processEvidence.Arguments,
                WorkingDirectory = processEvidence.WorkingDirectory,
                TestProjectPath = input.TestProjectPath,
                ResultsDirectory = input.ResultsDirectory,
                ArtifactPath = artifactPath,
                ArtifactExists = artifactExists,
                ArtifactSizeBytes = artifactSize,
                Status = artifactExists
                    ? CoverageCollectionStatus.Collected
                    : CoverageCollectionStatus.NotCollected,
                // H-01.4 honesty: exit 1 is ambiguous (tests failed OR build
                // failure) — TestsFailed is Unknown here; the authoritative
                // value comes from TRX parsing (H-03.5).
                TestsFailed = null
            };

            // Success = the collection ATTEMPT completed with process truth;
            // Status carries whether coverage was actually obtained (4.1.6).
            return ServiceResult<CoverageCollectionEvidence>.Success(evidence);
        }
        catch (Exception ex) when (ex is not ArgumentNullException
                                        and not ArgumentException
                                        and not ArgumentOutOfRangeException)
        {
            return ServiceResult<CoverageCollectionEvidence>.DiagnosticError(ex,
                nameof(CoverageCollectorService));
        }
    }

    /// <summary>Stage 3.1.2 continuity — working directory must exist.</summary>
    public string ValidateWorkingDirectory(string workingDirectory)
    {
        if (string.IsNullOrWhiteSpace(workingDirectory))
            throw new ArgumentException("Working directory is required.", nameof(workingDirectory));

        var full = Path.GetFullPath(workingDirectory);
        if (!Directory.Exists(full))
            throw new ArgumentException(
                $"Working directory does not exist: '{full}'.", nameof(workingDirectory));
        return full;
    }
}