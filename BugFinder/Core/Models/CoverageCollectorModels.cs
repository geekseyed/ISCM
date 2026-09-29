namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.1: Coverage Collector Contract Models
/// (audit KBF-06-001 P0: no authoritative Test->Lines pipeline existed;
/// per-test SBFL input was not a real artifact flow).
///
/// AUTHORITATIVE COLLECTOR (H-04.1.1): coverlet XPlat Code Coverage via
/// "dotnet test --collect" — the same collector the repo already ships.
///
/// CRITICAL SEMANTIC (KBF-06 fix seed): test outcome != coverage outcome.
/// Tests failing (exit code 1) does NOT invalidate the collected coverage
/// — TestsFailed=true + Status=Collected coexist by design.
///
/// H-04.1.6: Collected (artifact on disk) is distinct from
/// NotCollected (process ran, no artifact) — never fabricated as success.
/// </summary>
public enum CoverageCollectionStatus
{
    /// <summary>Artifact found on disk (parsing is H-04.2's job).</summary>
    Collected,

    /// <summary>Process ran to completion but produced no coverage artifact.</summary>
    NotCollected
}

/// <summary>H-04.1.1/4.1.2 — validated collection input (no defaults invented).</summary>
public sealed class CoverageCollectionInput
{
    public string WorkingDirectory { get; init; } = string.Empty;
    public string TestProjectPath { get; init; } = string.Empty;
    public string ResultsDirectory { get; init; } = string.Empty;
    public string Executable { get; init; } = "dotnet";
}

/// <summary>
/// H-04.1.3-4.1.5: collection evidence — process truth (H-03.1 continuity)
/// + resolved artifact identity + audit copy of the command.
/// </summary>
public sealed class CoverageCollectionEvidence
{
    // Process truth (H-03.1 continuity)
    public int? ProcessId { get; init; }
    public DateTimeOffset? StartUtc { get; init; }
    public DateTimeOffset? EndUtc { get; init; }
    public int? ExitCode { get; init; }
    public bool TerminatedByCancellation { get; init; }

    // H-04.1.2 — command audit copy
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();
    public string WorkingDirectory { get; init; } = string.Empty;
    public string TestProjectPath { get; init; } = string.Empty;
    public string ResultsDirectory { get; init; } = string.Empty;

    // H-04.1.4 — resolved artifact
    public string? ArtifactPath { get; init; }
    public bool ArtifactExists { get; init; }

    /// <summary>H-04.1.5 — metadata hint; zero bytes flags a suspicious artifact
    /// (parsing verdict belongs to H-04.2).</summary>
    public long? ArtifactSizeBytes { get; init; }

    // H-04.1.6 — explicit state
    public CoverageCollectionStatus Status { get; init; }

    /// <summary>
    /// KBF-06 semantic seed: tests failing does NOT invalidate coverage —
    /// exit code 1 with a produced artifact is still valid coverage.
    /// </summary>
    public bool? TestsFailed { get; init; }
}