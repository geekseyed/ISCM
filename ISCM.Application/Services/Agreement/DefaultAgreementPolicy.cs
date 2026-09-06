using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Services.Agreement;

/// <summary>
/// Default deterministic agreement policy for verification paths.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.2
/// 
/// Implements the deterministic matrix from Final Engineering Specification, Section 9.1:
/// 
///   PASS/PASS/PASS     → PASS candidate (FullAgreement)
///   FAIL/FAIL/FAIL     → FAIL (UnanimousFailure)
///   PASS/FAIL/FAIL     → DISAGREEMENT (never PASS)
///   PASS/PASS/FAIL     → DISAGREEMENT (never PASS)
///   PASS/ERROR/PASS    → ERROR (IncompleteVerification)
///   PASS/UNKNOWN/PASS  → UNKNOWN (IncompleteVerification)
/// 
/// Precedence (highest to lowest):
///   Error > Unknown > Disagreement > Fail > Pass
/// 
/// Hard rules enforced:
///   1. NEVER: disagreement → PASS
///   2. NEVER: unavailable path → silently ignored
///   3. NEVER: path result → overwritten by consensus
///   4. All path results preserved in AgreementDecision.PathContributions
/// 
/// This policy is:
///   - Deterministic: same inputs → same output
///   - Conservative: errors and unknowns propagate (no silent pass)
///   - Audit-friendly: all path results preserved
///   - Generic: works for any number of paths (not just 3)
/// </summary>
public class DefaultAgreementPolicy : IAgreementPolicy
{
    public string PolicyName => "DefaultAgreementPolicy";

    public string PolicyDescription =>
        "Deterministic agreement policy with precedence: Error > Unknown > Disagreement > Fail > Pass. " +
        "Never produces Pass when paths disagree or when any path is Error/Unknown.";

    /// <summary>
    /// Analyzes path results and produces an agreement decision
    /// using the deterministic matrix.
    /// </summary>
    public AgreementDecision Decide(IReadOnlyList<PathResult> pathResults)
    {
        if (pathResults == null)
            throw new ArgumentNullException(nameof(pathResults));

        // =====================================================================
        // Edge Case: No paths executed
        // =====================================================================
        if (pathResults.Count == 0)
        {
            return AgreementDecision.NoPaths(
                "No verification paths were executed. Cannot determine compliance.");
        }

        // =====================================================================
        // Count paths by status
        // =====================================================================
        var passCount = pathResults.Count(p => p.Status == CheckStatus.Pass);
        var failCount = pathResults.Count(p => p.Status == CheckStatus.Fail);
        var errorCount = pathResults.Count(p => p.Status == CheckStatus.Error);
        var unknownCount = pathResults.Count(p => p.Status == CheckStatus.Unknown);
        var notApplicableCount = pathResults.Count(p => p.Status == CheckStatus.NotApplicable);
        var disagreementCount = pathResults.Count(p => p.Status == CheckStatus.Disagreement);

        var totalPaths = pathResults.Count;
        var effectivePaths = totalPaths - notApplicableCount;

        // =====================================================================
        // Edge Case: All paths are NotApplicable
        // =====================================================================
        if (effectivePaths == 0)
        {
            return AgreementDecision.IncompleteVerification(
                CheckStatus.NotApplicable,
                $"All {totalPaths} paths are NotApplicable. No verification performed.",
                pathResults.ToList());
        }

        // =====================================================================
        // Rule 1: Any Error → ERROR (highest precedence)
        // =====================================================================
        if (errorCount > 0)
        {
            var errorPathIds = string.Join(", ",
                pathResults.Where(p => p.Status == CheckStatus.Error).Select(p => p.PathId));

            return AgreementDecision.IncompleteVerification(
                CheckStatus.Error,
                $"Verification incomplete: {errorCount} path(s) failed with Error " +
                $"({errorPathIds}). Precedence: Error overrides all other states.",
                pathResults.ToList());
        }

        // =====================================================================
        // Rule 2: Any Unknown → UNKNOWN (second highest precedence)
        // =====================================================================
        if (unknownCount > 0)
        {
            var unknownPathIds = string.Join(", ",
                pathResults.Where(p => p.Status == CheckStatus.Unknown).Select(p => p.PathId));

            return AgreementDecision.IncompleteVerification(
                CheckStatus.Unknown,
                $"Verification incomplete: {unknownCount} path(s) returned Unknown " +
                $"({unknownPathIds}). Cannot determine compliance with incomplete information.",
                pathResults.ToList());
        }

        // =====================================================================
        // Rule 3: Any Disagreement (nested) → DISAGREEMENT
        // =====================================================================
        if (disagreementCount > 0)
        {
            return AgreementDecision.Disagreement(
                $"One or more paths already reported Disagreement ({disagreementCount} path(s)). " +
                $"Propagating Disagreement state upward.",
                pathResults.ToList());
        }

        // =====================================================================
        // At this point: all effective paths are either Pass or Fail
        // =====================================================================

        // =====================================================================
        // Rule 4: All Pass → PASS (FullAgreement)
        // =====================================================================
        if (failCount == 0 && passCount == effectivePaths)
        {
            return AgreementDecision.FullAgreement(
                CheckStatus.Pass,
                $"All {passCount} effective path(s) agree on Pass. " +
                $"Strong evidence of compliance.",
                pathResults.ToList());
        }

        // =====================================================================
        // Rule 5: All Fail → FAIL (UnanimousFailure)
        // =====================================================================
        if (passCount == 0 && failCount == effectivePaths)
        {
            return AgreementDecision.UnanimousFailure(
                $"All {failCount} effective path(s) agree on Fail. " +
                $"Strong evidence of non-compliance.",
                pathResults.ToList());
        }

        // =====================================================================
        // Rule 6: Mix of Pass and Fail → DISAGREEMENT (NEVER PASS)
        // =====================================================================
        // This covers:
        //   - PASS/PASS/FAIL
        //   - PASS/FAIL/FAIL
        //   - PASS/FAIL
        //   - Any other mix of Pass and Fail

        return AgreementDecision.Disagreement(
            $"Paths disagree: {passCount} Pass, {failCount} Fail out of {effectivePaths} effective path(s). " +
            $"Contract rule: disagreement NEVER resolves to Pass. Requires human review or additional investigation.",
            pathResults.ToList());
    }

    // =========================================================================
    // Helper: Matrix Documentation
    // =========================================================================

    /// <summary>
    /// Returns a human-readable documentation of the agreement matrix.
    /// Useful for diagnostics and UI display.
    /// </summary>
    public static string GetMatrixDocumentation()
    {
        return @"
Default Agreement Policy — Deterministic Matrix
================================================

Precedence (highest to lowest):
  Error > Unknown > Disagreement > Fail > Pass

Matrix:
  PASS/PASS/PASS     → PASS      (FullAgreement)
  FAIL/FAIL/FAIL     → FAIL      (UnanimousFailure)
  PASS/FAIL/FAIL     → DISAGREEMENT (never PASS)
  PASS/PASS/FAIL     → DISAGREEMENT (never PASS)
  PASS/ERROR/PASS    → ERROR     (IncompleteVerification)
  PASS/UNKNOWN/PASS  → UNKNOWN   (IncompleteVerification)
  ERROR/*            → ERROR     (any Error overrides)
  UNKNOWN/*          → UNKNOWN   (any Unknown, no Error)
  empty paths        → UNKNOWN   (no evidence)
  all NotApplicable  → NotApplicable

Hard rules:
  - NEVER: disagreement → PASS
  - NEVER: unavailable path → silently ignored
  - NEVER: path result → overwritten by consensus
  - All path results preserved in PathContributions
";
    }
}