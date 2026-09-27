using System;
using System.Collections.Generic;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// BF-15.5: Advanced Regression Isolation Models (research only).
/// Narrows a candidate commit range to the first failing revision with
/// the minimal number of revision tests. Revision testing is a
/// caller-supplied gateway contract - the Core never checks out,
/// builds, or runs anything (Strict Core Boundary, BF-14.9).
/// Monotonicity contract: all commits before the first failing one
/// pass, all from it on fail (classic bisection precondition).
/// </summary>

public enum RegressionIsolationStatus
{
    Isolated,      // boundary located within the candidate range
    NoCandidates   // boundaries are adjacent - the known-failing boundary IS the first failure
}

public enum RevisionTestSource { Scripted, Real }

/// <summary>Evidence of one revision test performed during bisection.</summary>
public class RevisionTestRecord
{
    public string CommitId { get; set; } = string.Empty;
    public bool WasFailing { get; set; }
}

public class RegressionIsolationReport
{
    public string ScenarioName { get; set; } = string.Empty;
    public RegressionIsolationStatus Status { get; set; }

    // Trusted boundary inputs (from BF-10.3 / BF-10.4)
    public string BoundaryPassingCommitId { get; set; } = string.Empty;
    public string BoundaryFailingCommitId { get; set; } = string.Empty;

    // Stage 1 - candidate reduction
    public int InputCandidateCount { get; set; }
    public int DuplicateCount { get; set; }
    public int CandidateCount { get; set; }

    // Stage 3 - refined boundary
    public string? FirstFailingCommitId { get; set; }
    public string? LastPassingCommitId { get; set; }

    // Stage 2/4 - the minimal regression set (in test order)
    public List<string> TestedCommitIds { get; set; } = new();
    public List<RevisionTestRecord> Tests { get; set; } = new();
    public int TestCount { get; set; }

    /// <summary>ceil(log2(n+1)) - worst-case information-theoretic bound for n candidates.</summary>
    public int WorstCaseBound { get; set; }
    public bool WithinBound { get; set; }

    public bool MonotonicityAssumed { get; set; } = true;

    public bool IsExperimental { get; set; } = true;
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

    public const string DisclaimerText =
        "EXPERIMENTAL (BF-15.5): regression-isolation research evidence - not production guidance. " +
        "Revision testing is a caller gateway; the Core never checks out, builds, or runs revisions. " +
        "Bisection assumes monotonic pass/fail over the candidate range.";

    /// <summary>Serializable view (const strings are invisible to System.Text.Json - 15.7 lesson).</summary>
    public string Disclaimer => DisclaimerText;
}