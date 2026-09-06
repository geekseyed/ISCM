using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Services.Agreement;

/// <summary>
/// Service for applying agreement/disagreement analysis to SubControlResults.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.3
/// 
/// Responsibilities:
///   1. Take a SubControlResult with populated VerificationResults
///   2. Run IAgreementPolicy.Decide() on the path results
///   3. Apply the AgreementDecision to the SubControlResult
///   4. Return the updated result (with Status updated from SelectedVerdict)
/// 
/// Hard rules:
///   - All VerificationResults are preserved (never deleted)
///   - SubControlResult.Status is updated from AgreementDecision.SelectedVerdict
///   - If no paths exist, Status remains unchanged (legacy behavior)
///   - If agreement fails unexpectedly, Status is set to Error (not silent pass)
/// 
/// Backward compatibility:
///   - SubControls with 0 or 1 path continue to work (no agreement needed)
///   - Existing Status values are preserved when agreement is not applicable
/// </summary>
public class SubControlAggregationService
{
    private readonly IAgreementPolicy _agreementPolicy;

    public SubControlAggregationService(IAgreementPolicy agreementPolicy)
    {
        _agreementPolicy = agreementPolicy
            ?? throw new ArgumentNullException(nameof(agreementPolicy));
    }

    // =========================================================================
    // Single SubControl Aggregation
    // =========================================================================

    /// <summary>
    /// Applies agreement analysis to a single SubControlResult.
    /// 
    /// Flow:
    ///   1. If no path results exist, return unchanged (legacy behavior).
    ///   2. If only 1 path result exists, skip agreement (single-path is authoritative).
    ///   3. Run IAgreementPolicy.Decide() on all path results.
    ///   4. Apply AgreementDecision to SubControlResult.
    ///   5. Return the updated result.
    /// </summary>
    /// <param name="subControlResult">The SubControlResult to aggregate.</param>
    /// <returns>The same SubControlResult with AgreementDecision applied.</returns>
    public SubControlResult Aggregate(SubControlResult subControlResult)
    {
        if (subControlResult == null)
            throw new ArgumentNullException(nameof(subControlResult));

        // =====================================================================
        // Edge Case: No path results (legacy single-evidence checks)
        // =====================================================================
        if (subControlResult.VerificationResults.Count == 0)
        {
            // No paths → no agreement analysis.
            // Status remains as set by legacy evaluation.
            return subControlResult;
        }

        // =====================================================================
        // Edge Case: Single path (no agreement needed)
        // =====================================================================
        if (subControlResult.VerificationResults.Count == 1)
        {
            var singlePath = subControlResult.VerificationResults[0];

            // Single path is authoritative; use its status directly.
            // Still create an AgreementDecision for consistency and audit.
            var decision = AgreementDecision.FullAgreement(
                verdict: singlePath.Status,
                reason: $"Single path ({singlePath.PathId}) authoritative; no agreement analysis needed.",
                pathResults: subControlResult.VerificationResults.ToList());

            subControlResult.ApplyAgreementDecision(decision);
            return subControlResult;
        }

        // =====================================================================
        // Multi-path: Run agreement policy
        // =====================================================================
        try
        {
            var pathResults = subControlResult.VerificationResults.ToList();
            var decision = _agreementPolicy.Decide(pathResults);

            // Apply decision to SubControlResult
            subControlResult.ApplyAgreementDecision(decision);
        }
        catch (Exception ex)
        {
            // Agreement failed unexpectedly — set Error, never silent pass.
            var errorDecision = AgreementDecision.NoPaths(
                $"Agreement analysis failed unexpectedly: {ex.Message}. " +
                $"This is an internal error, not a compliance verdict.");

            subControlResult.ApplyAgreementDecision(errorDecision);
            subControlResult.Status = Domain.Enums.CheckStatus.Error;
        }

        return subControlResult;
    }

    // =========================================================================
    // Batch Aggregation
    // =========================================================================

    /// <summary>
    /// Applies agreement analysis to a list of SubControlResults.
    /// 
    /// Each SubControlResult is processed independently.
    /// Failure of one SubControl does not affect others.
    /// </summary>
    /// <param name="subControlResults">The list of SubControlResults to aggregate.</param>
    /// <returns>The same list with AgreementDecision applied to each result.</returns>
    public List<SubControlResult> AggregateAll(List<SubControlResult> subControlResults)
    {
        if (subControlResults == null)
            throw new ArgumentNullException(nameof(subControlResults));

        foreach (var result in subControlResults)
        {
            try
            {
                Aggregate(result);
            }
            catch (Exception)
            {
                // Individual failure should not break the batch.
                // Error is already set by Aggregate() catch block.
                continue;
            }
        }

        return subControlResults;
    }

    // =========================================================================
    // Analysis Helpers
    // =========================================================================

    /// <summary>
    /// Gets SubControlResults that have disagreement.
    /// </summary>
    public List<SubControlResult> GetDisagreements(List<SubControlResult> results)
    {
        if (results == null)
            throw new ArgumentNullException(nameof(results));

        return results
            .Where(r => r.AgreementDecision?.AgreementState ==
                        Domain.Enums.AgreementState.Disagreement)
            .ToList();
    }

    /// <summary>
    /// Gets SubControlResults that have incomplete verification.
    /// </summary>
    public List<SubControlResult> GetIncompleteVerifications(List<SubControlResult> results)
    {
        if (results == null)
            throw new ArgumentNullException(nameof(results));

        return results
            .Where(r => r.AgreementDecision?.AgreementState ==
                        Domain.Enums.AgreementState.IncompleteVerification)
            .ToList();
    }

    /// <summary>
    /// Gets summary counts for a list of SubControlResults.
    /// </summary>
    public AgreementSummary GetSummary(List<SubControlResult> results)
    {
        if (results == null)
            throw new ArgumentNullException(nameof(results));

        var summary = new AgreementSummary
        {
            TotalSubControls = results.Count,
            PassCount = results.Count(r => r.Status == Domain.Enums.CheckStatus.Pass),
            FailCount = results.Count(r => r.Status == Domain.Enums.CheckStatus.Fail),
            ErrorCount = results.Count(r => r.Status == Domain.Enums.CheckStatus.Error),
            UnknownCount = results.Count(r => r.Status == Domain.Enums.CheckStatus.Unknown),
            DisagreementCount = results.Count(r =>
                r.AgreementDecision?.AgreementState == Domain.Enums.AgreementState.Disagreement),
            IncompleteCount = results.Count(r =>
                r.AgreementDecision?.AgreementState == Domain.Enums.AgreementState.IncompleteVerification),
            FullAgreementCount = results.Count(r =>
                r.AgreementDecision?.AgreementState == Domain.Enums.AgreementState.FullAgreement),
            UnanimousFailureCount = results.Count(r =>
                r.AgreementDecision?.AgreementState == Domain.Enums.AgreementState.UnanimousFailure)
        };

        return summary;
    }
}

// =========================================================================
// AgreementSummary — result VO for batch analysis
// =========================================================================

/// <summary>
/// Summary of agreement analysis across multiple SubControls.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.3
/// </summary>
public class AgreementSummary
{
    public int TotalSubControls { get; set; }

    public int PassCount { get; set; }

    public int FailCount { get; set; }

    public int ErrorCount { get; set; }

    public int UnknownCount { get; set; }

    public int DisagreementCount { get; set; }

    public int IncompleteCount { get; set; }

    public int FullAgreementCount { get; set; }

    public int UnanimousFailureCount { get; set; }

    /// <summary>
    /// Whether any SubControl has disagreement.
    /// </summary>
    public bool HasDisagreement => DisagreementCount > 0;

    /// <summary>
    /// Whether any SubControl has incomplete verification.
    /// </summary>
    public bool HasIncompleteVerification => IncompleteCount > 0;

    public override string ToString()
        => $"[Total={TotalSubControls}, Pass={PassCount}, Fail={FailCount}, " +
           $"Error={ErrorCount}, Unknown={UnknownCount}, " +
           $"Disagreement={DisagreementCount}, Incomplete={IncompleteCount}]";
}