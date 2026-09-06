using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.Entities;

/// <summary>
/// Result of evaluating a single SubControl.
/// 
/// Phase 9.3: Added Agreement Decision support:
///   - AgreementDecision: stores the outcome of agreement/disagreement analysis
///   - ApplyAgreementDecision(): applies decision to Status and metadata
/// 
/// Backward compatibility:
///   - All existing properties preserved
///   - AgreementDecision is nullable (null when agreement not performed)
/// </summary>
public class SubControlResult
{
    // =========================================================================
    // Identity & Status
    // =========================================================================

    public string SubControlId { get; set; } = string.Empty;

    public CheckStatus Status { get; set; } = CheckStatus.Unknown;

    // =========================================================================
    // Evidence
    // =========================================================================

    public List<Evidence> EvidenceItems { get; set; } = new();

    public List<string> EvidenceReferences { get; set; } = new();

    // =========================================================================
    // Verification Results (Phase 8.4)
    // =========================================================================

    /// <summary>
    /// Results of each verification path execution.
    /// One PathResult per VerificationPath per scan.
    /// </summary>
    public List<PathResult> VerificationResults { get; set; } = new();

    /// <summary>
    /// Path capability validation report for this SubControl.
    /// Null if capability validation was not performed.
    /// </summary>
    public PathCapabilityReport? PathCapabilityReport { get; set; }

    // =========================================================================
    // Phase 9.3 — NEW: Agreement Decision
    // =========================================================================

    /// <summary>
    /// The outcome of agreement/disagreement analysis on VerificationResults.
    /// Null when agreement analysis has not been performed
    /// (e.g., legacy single-path checks, or pre-Phase-9 scans).
    /// </summary>
    public AgreementDecision? AgreementDecision { get; set; }

    /// <summary>
    /// Whether agreement analysis has been performed on this SubControl.
    /// </summary>
    public bool HasAgreementDecision => AgreementDecision != null;

    // =========================================================================
    // Timing
    // =========================================================================

    public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;

    // =========================================================================
    // Helper Methods (Phase 8.4)
    // =========================================================================

    /// <summary>
    /// Adds a PathResult to VerificationResults.
    /// </summary>
    public void AddPathResult(PathResult pathResult)
    {
        if (pathResult == null)
            throw new ArgumentNullException(nameof(pathResult));

        VerificationResults.Add(pathResult);
    }

    /// <summary>
    /// Gets path results filtered by status.
    /// </summary>
    public List<PathResult> GetPathResultsByStatus(CheckStatus status)
        => VerificationResults.Where(p => p.Status == status).ToList();

    /// <summary>
    /// Gets path results that were skipped.
    /// </summary>
    public List<PathResult> GetSkippedPathResults()
        => VerificationResults.Where(p => p.WasSkipped).ToList();

    /// <summary>
    /// Count of path results.
    /// </summary>
    public int PathResultCount => VerificationResults.Count;

    /// <summary>
    /// Whether all path results are Pass.
    /// </summary>
    public bool AllPathsPass =>
        VerificationResults.Count > 0 &&
        VerificationResults.All(p => p.Status == CheckStatus.Pass);

    /// <summary>
    /// Whether any path result is Error.
    /// </summary>
    public bool AnyPathError =>
        VerificationResults.Any(p => p.Status == CheckStatus.Error);

    /// <summary>
    /// Whether any path result is Fail.
    /// </summary>
    public bool AnyPathFail =>
        VerificationResults.Any(p => p.Status == CheckStatus.Fail);

    /// <summary>
    /// Gets a PathResult by PathId.
    /// </summary>
    public PathResult? GetPathResult(string pathId)
        => VerificationResults.FirstOrDefault(p => p.PathId == pathId);

    // =========================================================================
    // Phase 9.3 — NEW: Agreement Application
    // =========================================================================

    /// <summary>
    /// Applies an AgreementDecision to this SubControlResult.
    /// 
    /// This method:
    ///   1. Stores the AgreementDecision
    ///   2. Updates Status from SelectedVerdict
    ///   3. Updates EvaluatedAt
    ///   4. PRESERVES all VerificationResults (no deletion)
    /// 
    /// Hard rule: VerificationResults are NEVER cleared.
    /// The agreement decision references them via PathContributions.
    /// </summary>
    public void ApplyAgreementDecision(AgreementDecision decision)
    {
        if (decision == null)
            throw new ArgumentNullException(nameof(decision));

        AgreementDecision = decision;
        Status = decision.SelectedVerdict;
        EvaluatedAt = DateTime.UtcNow;

        // IMPORTANT: VerificationResults are NOT cleared.
        // All path results remain preserved for audit/UI consumption.
    }
}