using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-15.5: Advanced Regression Isolation Service
/// Stage 1 Candidate Commit Reduction: dedupe candidates preserving
///          chronological order (caller supplies oldest -> newest).
/// Stage 2 Automated Revision Testing: IRevisionTestGateway contract;
///          ScriptedRevisionTestGateway ships in-Core for research
///          (deterministic truth set); real executors live outside.
/// Stage 3 Regression Boundary Refinement: bisection between the
///          trusted boundaries - each test halves the unknown interval.
/// Stage 4 Minimal Regression Set: the tested commits are the minimal
///          adaptive set - bisection never exceeds ceil(log2(n+1)) tests.
/// Boundaries are trusted inputs (BF-10.3 last-known-passing /
/// BF-10.4 first-known-failing); this phase refines between them.
/// Midpoint computed as lo + (hi - lo) / 2 (overflow-safe).
/// </summary>
public class RegressionIsolationService
{
    public RegressionIsolationReport Isolate(
        string scenarioName,
        IReadOnlyList<string> candidatesChronological,
        string boundaryPassingCommitId,
        string boundaryFailingCommitId,
        IRevisionTestGateway gateway)
    {
        if (scenarioName is null) throw new ArgumentNullException(nameof(scenarioName));
        if (candidatesChronological is null) throw new ArgumentNullException(nameof(candidatesChronological));
        if (gateway is null) throw new ArgumentNullException(nameof(gateway));
        if (string.IsNullOrWhiteSpace(boundaryPassingCommitId))
            throw new ArgumentException("Passing boundary commit id is required.", nameof(boundaryPassingCommitId));
        if (string.IsNullOrWhiteSpace(boundaryFailingCommitId))
            throw new ArgumentException("Failing boundary commit id is required.", nameof(boundaryFailingCommitId));

        var report = new RegressionIsolationReport
        {
            ScenarioName = scenarioName,
            BoundaryPassingCommitId = boundaryPassingCommitId,
            BoundaryFailingCommitId = boundaryFailingCommitId,
            InputCandidateCount = candidatesChronological.Count
        };

        // Stage 1 - reduction: dedupe, preserve first-occurrence (chronological) order
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var candidates = new List<string>();
        foreach (var commit in candidatesChronological)
        {
            if (seen.Add(commit)) candidates.Add(commit);
            else report.DuplicateCount++;
        }
        report.CandidateCount = candidates.Count;

        // Stage 4 - worst-case bound (0 tests needed when nothing is unknown)
        report.WorstCaseBound = candidates.Count == 0
            ? 0
            : (int)Math.Ceiling(Math.Log2(candidates.Count + 1));

        // Stage 4 - trivial case: boundaries adjacent, the known-failing IS the first failure
        if (candidates.Count == 0)
        {
            report.Status = RegressionIsolationStatus.NoCandidates;
            report.FirstFailingCommitId = boundaryFailingCommitId;
            report.LastPassingCommitId = boundaryPassingCommitId;
            report.WithinBound = true;
            return report;
        }

        // Stages 2-3 - bisection over [P, candidates..., F]
        // index 0 = passing boundary, index candidates.Count+1 = failing boundary
        string CommitAt(int index) =>
            index == 0 ? boundaryPassingCommitId
            : index == candidates.Count + 1 ? boundaryFailingCommitId
            : candidates[index - 1];

        var lo = 0;                          // known passing
        var hi = candidates.Count + 1;       // known failing

        while (hi - lo > 1)
        {
            var mid = lo + (hi - lo) / 2;    // overflow-safe midpoint
            var commit = CommitAt(mid);
            var failing = gateway.IsFailing(commit);

            report.Tests.Add(new RevisionTestRecord { CommitId = commit, WasFailing = failing });
            if (failing) hi = mid; else lo = mid;
        }

        // Stage 4 - refined boundary + minimal set
        report.Status = RegressionIsolationStatus.Isolated;
        report.FirstFailingCommitId = CommitAt(hi);
        report.LastPassingCommitId = CommitAt(lo);
        report.TestedCommitIds = report.Tests.Select(t => t.CommitId).ToList();
        report.TestCount = report.Tests.Count;
        report.WithinBound = report.TestCount <= report.WorstCaseBound;

        return report;
    }
}

/// <summary>
/// Stage 2 contract: real revision executors live OUTSIDE the Core
/// (they check out / build / run - forbidden by BF-14.9).
/// </summary>
public interface IRevisionTestGateway
{
    RevisionTestSource Source { get; }

    /// <summary>true = the revision reproduces the failure.</summary>
    bool IsFailing(string commitId);
}

/// <summary>
/// Deterministic in-Core research gateway driven by a truth set
/// (the commits known to fail). Tracks CallCount so tests can assert
/// exactly how many revision tests bisection consumed.
/// </summary>
public class ScriptedRevisionTestGateway : IRevisionTestGateway
{
    private readonly HashSet<string> _failing;

    public RevisionTestSource Source => RevisionTestSource.Scripted;
    public int CallCount { get; private set; }

    public ScriptedRevisionTestGateway(IEnumerable<string> failingCommitIds)
    {
        if (failingCommitIds is null) throw new ArgumentNullException(nameof(failingCommitIds));
        _failing = new HashSet<string>(failingCommitIds, StringComparer.Ordinal);
    }

    public bool IsFailing(string commitId)
    {
        CallCount++;
        return _failing.Contains(commitId);
    }
}