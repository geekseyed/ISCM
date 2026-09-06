using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Immutable value object representing the outcome of the agreement engine.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.1
/// 
/// Contract:
///   - SelectedVerdict: the final CheckStatus for the SubControl
///   - AgreementState: classification of how paths agreed/disagreed
///   - Reason: human-readable explanation of the decision
///   - PathContributions: breakdown of how each path contributed
///   - DecidedAtUtc: timestamp of decision
/// 
/// Hard rules:
///   1. SelectedVerdict is NEVER Pass when AgreementState = Disagreement
///   2. SelectedVerdict is NEVER Pass when any path is Error/Unknown
///   3. All original PathResult objects are preserved (no overwriting)
///   4. Decision is deterministic: same inputs → same output
/// </summary>
public sealed class AgreementDecision
{
    // =========================================================================
    // Core Decision
    // =========================================================================

    /// <summary>
    /// The final verdict for the SubControl after agreement analysis.
    /// </summary>
    public CheckStatus SelectedVerdict { get; }

    /// <summary>
    /// Classification of how paths agreed or disagreed.
    /// </summary>
    public AgreementState AgreementState { get; }

    /// <summary>
    /// Human-readable explanation of why this verdict was selected.
    /// </summary>
    public string Reason { get; }

    // =========================================================================
    // Path Contributions (Audit Trail)
    // =========================================================================

    /// <summary>
    /// Breakdown of how each path contributed to the decision.
    /// Key: PathId, Value: (Status, Contribution).
    /// Preserves all original path results for audit/UI.
    /// </summary>
    public IReadOnlyDictionary<string, PathContribution> PathContributions { get; }

    /// <summary>
    /// Number of paths that were Pass.
    /// </summary>
    public int PassCount { get; }

    /// <summary>
    /// Number of paths that were Fail.
    /// </summary>
    public int FailCount { get; }

    /// <summary>
    /// Number of paths that were Error.
    /// </summary>
    public int ErrorCount { get; }

    /// <summary>
    /// Number of paths that were Unknown.
    /// </summary>
    public int UnknownCount { get; }

    /// <summary>
    /// Total number of paths analyzed.
    /// </summary>
    public int TotalPathCount { get; }

    // =========================================================================
    // Timing
    // =========================================================================

    /// <summary>
    /// When this decision was made (UTC).
    /// </summary>
    public DateTime DecidedAtUtc { get; }

    // =========================================================================
    // Constructor (private — use factory methods)
    // =========================================================================

    private AgreementDecision(
        CheckStatus selectedVerdict,
        AgreementState agreementState,
        string reason,
        IReadOnlyDictionary<string, PathContribution> pathContributions)
    {
        SelectedVerdict = selectedVerdict;
        AgreementState = agreementState;
        Reason = reason ?? string.Empty;
        PathContributions = pathContributions ?? new Dictionary<string, PathContribution>();
        DecidedAtUtc = DateTime.UtcNow;

        // Compute counts
        PassCount = PathContributions.Values.Count(p => p.Status == CheckStatus.Pass);
        FailCount = PathContributions.Values.Count(p => p.Status == CheckStatus.Fail);
        ErrorCount = PathContributions.Values.Count(p => p.Status == CheckStatus.Error);
        UnknownCount = PathContributions.Values.Count(p => p.Status == CheckStatus.Unknown);
        TotalPathCount = PathContributions.Count;
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// <summary>
    /// Create a decision where all paths agree (typically on Pass).
    /// </summary>
    public static AgreementDecision FullAgreement(
        CheckStatus verdict,
        string reason,
        IReadOnlyList<PathResult> pathResults)
    {
        var contributions = BuildContributions(pathResults, "Full agreement");
        return new AgreementDecision(verdict, AgreementState.FullAgreement, reason, contributions);
    }

    /// <summary>
    /// Create a decision where all paths agree on Fail.
    /// </summary>
    public static AgreementDecision UnanimousFailure(
        string reason,
        IReadOnlyList<PathResult> pathResults)
    {
        var contributions = BuildContributions(pathResults, "Unanimous failure");
        return new AgreementDecision(CheckStatus.Fail, AgreementState.UnanimousFailure, reason, contributions);
    }

    /// <summary>
    /// Create a decision where paths disagree (never Pass).
    /// </summary>
    public static AgreementDecision Disagreement(
        string reason,
        IReadOnlyList<PathResult> pathResults)
    {
        var contributions = BuildContributions(pathResults, "Disagreement");
        return new AgreementDecision(CheckStatus.Disagreement, AgreementState.Disagreement, reason, contributions);
    }

    /// <summary>
    /// Create a decision where verification is incomplete (Error/Unknown paths).
    /// </summary>
    public static AgreementDecision IncompleteVerification(
        CheckStatus verdict,
        string reason,
        IReadOnlyList<PathResult> pathResults)
    {
        var contributions = BuildContributions(pathResults, "Incomplete verification");
        return new AgreementDecision(verdict, AgreementState.IncompleteVerification, reason, contributions);
    }

    /// <summary>
    /// Create a decision where majority of paths agree (rare, 4+ paths).
    /// </summary>
    public static AgreementDecision MajorityAgreement(
        CheckStatus verdict,
        string reason,
        IReadOnlyList<PathResult> pathResults)
    {
        var contributions = BuildContributions(pathResults, "Majority agreement");
        return new AgreementDecision(verdict, AgreementState.MajorityAgreement, reason, contributions);
    }

    /// <summary>
    /// Create a decision for edge case: no paths executed.
    /// </summary>
    public static AgreementDecision NoPaths(string reason)
    {
        return new AgreementDecision(
            CheckStatus.Unknown,
            AgreementState.IncompleteVerification,
            reason,
            new Dictionary<string, PathContribution>());
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// <summary>
    /// Builds the PathContributions dictionary from path results.
    /// </summary>
    private static IReadOnlyDictionary<string, PathContribution> BuildContributions(
        IReadOnlyList<PathResult> pathResults,
        string contributionType)
    {
        var contributions = new Dictionary<string, PathContribution>();

        foreach (var path in pathResults)
        {
            contributions[path.PathId] = new PathContribution(
                pathId: path.PathId,
                status: path.Status,
                contribution: contributionType,
                evidenceId: path.EvidenceId,
                detail: path.EvaluationDetail);
        }

        return contributions;
    }

    /// <summary>
    /// Gets the PathIds that contributed Pass.
    /// </summary>
    public IEnumerable<string> GetPassPathIds()
        => PathContributions.Where(kv => kv.Value.Status == CheckStatus.Pass).Select(kv => kv.Key);

    /// <summary>
    /// Gets the PathIds that contributed Fail.
    /// </summary>
    public IEnumerable<string> GetFailPathIds()
        => PathContributions.Where(kv => kv.Value.Status == CheckStatus.Fail).Select(kv => kv.Key);

    /// <summary>
    /// Gets the PathIds that contributed Error.
    /// </summary>
    public IEnumerable<string> GetErrorPathIds()
        => PathContributions.Where(kv => kv.Value.Status == CheckStatus.Error).Select(kv => kv.Key);

    /// <summary>
    /// Gets the PathIds that contributed Unknown.
    /// </summary>
    public IEnumerable<string> GetUnknownPathIds()
        => PathContributions.Where(kv => kv.Value.Status == CheckStatus.Unknown).Select(kv => kv.Key);

    // =========================================================================
    // Overrides
    // =========================================================================

    public override string ToString()
        => $"[{SelectedVerdict}] State={AgreementState}, Pass={PassCount}, Fail={FailCount}, Error={ErrorCount}, Unknown={UnknownCount}, Reason={Reason}";

    public override bool Equals(object? obj)
    {
        if (obj is not AgreementDecision other)
            return false;

        return SelectedVerdict == other.SelectedVerdict &&
               AgreementState == other.AgreementState &&
               PassCount == other.PassCount &&
               FailCount == other.FailCount &&
               ErrorCount == other.ErrorCount &&
               UnknownCount == other.UnknownCount;
    }

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + SelectedVerdict.GetHashCode();
            hash = hash * 31 + AgreementState.GetHashCode();
            hash = hash * 31 + PassCount;
            hash = hash * 31 + FailCount;
            hash = hash * 31 + ErrorCount;
            hash = hash * 31 + UnknownCount;
            return hash;
        }
    }
}

// =========================================================================
// PathContribution — nested VO for audit trail
// =========================================================================

/// <summary>
/// Describes how a single path contributed to the agreement decision.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.1
/// </summary>
public sealed class PathContribution
{
    /// <summary>
    /// The PathId this contribution belongs to.
    /// </summary>
    public string PathId { get; }

    /// <summary>
    /// The status this path produced.
    /// </summary>
    public CheckStatus Status { get; }

    /// <summary>
    /// How this path contributed (e.g., "Full agreement", "Disagreement").
    /// </summary>
    public string Contribution { get; }

    /// <summary>
    /// The EvidenceId this path produced (if any).
    /// </summary>
    public string? EvidenceId { get; }

    /// <summary>
    /// The evaluation detail from the path.
    /// </summary>
    public string Detail { get; }

    public PathContribution(
        string pathId,
        CheckStatus status,
        string contribution,
        string? evidenceId,
        string detail)
    {
        PathId = pathId ?? throw new ArgumentNullException(nameof(pathId));
        Status = status;
        Contribution = contribution ?? string.Empty;
        EvidenceId = evidenceId;
        Detail = detail ?? string.Empty;
    }

    public override string ToString()
        => $"[PathId={PathId}, Status={Status}, Contribution={Contribution}]";
}