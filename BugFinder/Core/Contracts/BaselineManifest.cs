using System;
using System.Collections.Generic;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.1: Baseline Identity Contract.
/// Binds the Bug Finder baseline to repository identity, executable
/// state and test execution, so phase-completion claims are tied to a
/// specific, reproducible state (audit KBF-00-001 / KBF-00-002:
/// the stale PHASE0-INVENTORY documented a different branch/commit).
/// Schema versioning is seeded here (H-01.1) and generalized in H-01.3.
/// </summary>
public sealed class BaselineManifest
{
    public const int CurrentSchemaVersion = 1;

    // ---- H-01.3 seed: persisted contract versioning ----
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    // ---- H-01.1.1: repository identity ----
    public string RepositoryId { get; init; } = string.Empty;        // "geekseyed/ISCM"
    public string Branch { get; init; } = string.Empty;              // manifest owner branch
    public string CommitSha { get; init; } = string.Empty;           // manifest owner HEAD
    public DateTimeOffset RecordedAtUtc { get; init; }

    /// <summary>
    /// Audit anchor: the independently audited HEAD this hardening line
    /// descends from (diagnostics/phase15 @ 86e0b257...). Stale phase
    /// claims are detected against this anchor (H-01.1.4).
    /// </summary>
    public string AuditedHeadSha { get; init; } = string.Empty;

    // ---- H-01.1.2: executable state ----
    public string SolutionName { get; init; } = string.Empty;        // "ISCM.sln"
    public string TargetFramework { get; init; } = string.Empty;     // "net8.0"
    public string TestFramework { get; init; } = string.Empty;       // "xunit 2.7.0"
    public string TestSdkVersion { get; init; } = string.Empty;      // "17.9.0"
    public string BuildConfiguration { get; init; } = "Debug";

    // ---- H-01.1.3: test execution ----
    public string TestCommand { get; init; } = string.Empty;
    public string? ResultArtifactPath { get; init; }
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public int SkippedCount { get; init; }
    public TimeSpan ExecutionDuration { get; init; }
}

/// <summary>Raw inputs for manifest construction (no derived fields).</summary>
public sealed class BaselineManifestInput
{
    public string RepositoryId { get; init; } = string.Empty;
    public string Branch { get; init; } = string.Empty;
    public string CommitSha { get; init; } = string.Empty;
    public DateTimeOffset RecordedAtUtc { get; init; }
    public string AuditedHeadSha { get; init; } = string.Empty;
    public string SolutionName { get; init; } = string.Empty;
    public string TargetFramework { get; init; } = string.Empty;
    public string TestFramework { get; init; } = string.Empty;
    public string TestSdkVersion { get; init; } = string.Empty;
    public string BuildConfiguration { get; init; } = "Debug";
    public string TestCommand { get; init; } = string.Empty;
    public string? ResultArtifactPath { get; init; }
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public int SkippedCount { get; init; }
    public TimeSpan ExecutionDuration { get; init; }
}

public enum BaselineMatchStatus
{
    Identical,     // branch/SHA/counts all match
    Different,     // stale references found (H-01.1.4)
    Incomparable   // schema version mismatch (H-01.3 seed)
}

/// <summary>H-01.1.4/1.1.5: verification outcome — gate fails on any finding.</summary>
public sealed class BaselineVerificationReport
{
    public BaselineMatchStatus Status { get; init; }
    public List<string> StaleReferences { get; init; } = new();

    public bool GatePassed =>
        Status == BaselineMatchStatus.Identical && StaleReferences.Count == 0;
}