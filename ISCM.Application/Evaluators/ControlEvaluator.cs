using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Evaluators;

public class ControlEvaluator : IControlEvaluator
{
    // =========================================================================
    // Phase 7.5: Injected typed evaluator
    // =========================================================================

    private readonly ITypedEvidenceEvaluator _typedEvidenceEvaluator;

    /// <summary>
    /// Constructor with typed evidence evaluator injection (Phase 7.5).
    /// 
    /// The typed evaluator enables typed, unit-aware evaluation of Evidence items
    /// via ITypedEvidenceEvaluator. Legacy callers that do not need typed evaluation
    /// can still use the parameterless constructor (kept for backward compatibility
    /// during the migration period).
    /// </summary>
    public ControlEvaluator(ITypedEvidenceEvaluator typedEvidenceEvaluator)
    {
        _typedEvidenceEvaluator = typedEvidenceEvaluator
            ?? throw new ArgumentNullException(nameof(typedEvidenceEvaluator));
    }

    /// <summary>
    /// Backward-compatible parameterless constructor.
    /// Used by legacy code paths that do not need typed evaluation.
    /// Typed evaluation methods will throw if called on an instance created this way.
    /// </summary>
    public ControlEvaluator()
    {
        _typedEvidenceEvaluator = null!;
    }

    // =========================================================================
    // Legacy methods (UNCHANGED from pre-Phase-7 code)
    // =========================================================================

    public ControlResult Evaluate(ControlDefinition controlDefinition, IEnumerable<SubControlResult> subControlResults)
    {
        var results = subControlResults?.ToList() ?? new List<SubControlResult>();

        var controlResult = new ControlResult
        {
            ControlId = controlDefinition?.ControlId ?? "Unknown",
            EvaluatedAt = DateTime.UtcNow
        };

        if (results.Count == 0)
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        controlResult.SubControlResults = results;

        var applicable = results.Where(r => r.Status != CheckStatus.NotApplicable).ToList();

        if (applicable.Count == 0)
        {
            controlResult.Status = CheckStatus.NotApplicable;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Error))
        {
            controlResult.Status = CheckStatus.Error;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Fail))
        {
            controlResult.Status = CheckStatus.Fail;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Unknown))
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        if (applicable.All(r => r.Status == CheckStatus.Pass))
        {
            controlResult.Status = CheckStatus.Pass;
            return controlResult;
        }

        controlResult.Status = CheckStatus.Unknown;
        return controlResult;
    }

    public Finding EvaluateFromSubControls(ControlDefinition controlDefinition, List<SubControlResult> subControlResults, string? checkId = null)
    {
        var controlResult = Evaluate(controlDefinition, subControlResults);
        var allEvidence = subControlResults.SelectMany(s => s.EvidenceItems).ToList();

        var primaryCheckId = checkId
            ?? controlDefinition.TechnicalCheckIds.FirstOrDefault()
            ?? controlDefinition.ControlId;

        var finding = new Finding(
            checkId: primaryCheckId,
            name: controlDefinition.Title,
            category: controlDefinition.Category,
            severity: controlDefinition.Severity,
            status: controlResult.Status,
            currentValue: allEvidence.FirstOrDefault()?.RawOutput ?? "No evidence collected",
            expectedValue: subControlResults.FirstOrDefault()?.EvidenceItems.FirstOrDefault()?.ExpectedValue ?? "N/A",
            description: controlDefinition.Description,
            errorMessage: null,
            registryPath: string.Empty,
            cisReference: controlDefinition.BaselineId,
            riskScore: (int)controlDefinition.Severity * 20,
            sourceType: "Multi-Source Evidence",
            sourceCommand: string.Join(", ", allEvidence.Select(e => e.SourceName).Distinct()),
            fixTools: new List<string>(),
            subChecks: null,
            recommendation: $"Review and harden: {controlDefinition.Title}"
        );

        foreach (var evidence in allEvidence)
        {
            finding.AddTestResult(new TestResult(
                evidence.SourceType.ToString(),
                evidence.SourceName,
                evidence.Evaluation == CheckStatus.Pass,
                evidence.RawOutput
            ));
        }

        return finding;
    }

    public ControlResult EvaluateFromFindings(ControlDefinition controlDefinition, IEnumerable<Finding> findings)
    {
        var findingsList = findings?.ToList() ?? new List<Finding>();

        var subControlResults = findingsList.Select(f =>
        {
            Enum.TryParse<EvidenceSourceType>(f.SourceType, true, out var parsedSourceType);

            return new SubControlResult
            {
                SubControlId = f.CheckId,
                Status = f.Status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Unknown,
                        SourceName = f.SourceCommand,
                        RawOutput = f.CurrentValue,
                        ExpectedValue = f.ExpectedValue,
                        Evaluation = f.Status,
                        CollectedAtUtc = DateTime.UtcNow
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }).ToList();

        return Evaluate(controlDefinition, subControlResults);
    }

    // =========================================================================
    // Phase 7.5 — NEW: Typed SubControl evaluation
    // =========================================================================

    /// <summary>
    /// Evaluates a single SubControl using the typed evidence evaluator.
    /// 
    /// This is the NEW typed evaluation path introduced in Phase 7.5.
    /// It is intended to replace legacy string-based evaluation during the migration
    /// period (Phase 7.6 onwards, where the scanner will call this method directly).
    /// 
    /// Flow:
    ///   1. Validate SubControlResult and its EvidenceItems are not empty.
    ///   2. For each Evidence item:
    ///      a. Call ITypedEvidenceEvaluator.Evaluate(evidence, expectedString, expectedType, op)
    ///      b. Collect the EvaluationResult
    ///      c. Update Evidence.Evaluation and Evidence.EvaluationReason based on the result
    ///   3. Aggregate all per-Evidence results into a SubControl-level CheckStatus:
    ///      - Any Error       → Error (precedence)
    ///      - Any Unknown     → Unknown
    ///      - Any Fail        → Fail
    ///      - All Pass        → Pass
    ///      - No evidence     → Unknown
    ///   4. Update SubControlResult.Status with the aggregated status.
    ///   5. Return a SubControlEvaluationSummary with details for audit/UI.
    /// 
    /// Hard rules:
    ///   - If an Evidence item has TypedValue == null, ITypedEvidenceEvaluator returns Error
    ///     (normalization failure, not silent fallback). This Error propagates to the SubControl.
    ///   - If _typedEvidenceEvaluator is null (parameterless constructor used), throws.
    ///     Callers must use the DI-injected constructor to access typed evaluation.
    /// 
    /// Phase 7 — Typed Evaluation, Sub-Phase 7.5
    /// </summary>
    /// <param name="subControlResult">The SubControlResult to evaluate. Must have EvidenceItems.</param>
    /// <param name="expectedValueString">The expected value string from the catalog (e.g., "14 characters").</param>
    /// <param name="expectedType">The declared type from the catalog.</param>
    /// <param name="op">The declared operator from the catalog.</param>
    /// <returns>
    /// SubControlEvaluationSummary containing:
    ///   - AggregatedStatus (the final SubControl verdict)
    ///   - AggregatedReason (human-readable summary)
    ///   - PerEvidenceResults (list of EvaluationResult for each Evidence item)
    /// The SubControlResult.Status is ALSO updated in place for consistency.
    /// </returns>
    public SubControlEvaluationSummary EvaluateSubControlTyped(
        SubControlResult subControlResult,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op)
    {
        if (_typedEvidenceEvaluator == null)
        {
            throw new InvalidOperationException(
                "EvaluateSubControlTyped requires a ControlEvaluator constructed with " +
                "ITypedEvidenceEvaluator. Use the DI-injected constructor.");
        }

        if (subControlResult == null)
        {
            throw new ArgumentNullException(nameof(subControlResult));
        }

        var evidenceItems = subControlResult.EvidenceItems?.ToList() ?? new List<Evidence>();

        if (evidenceItems.Count == 0)
        {
            var noEvidenceResult = EvaluationResult.Unknown(
                "SubControl has no evidence items. Cannot evaluate.",
                EvaluationResult.BuildDetails(
                    actual: "(no evidence)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString()));

            subControlResult.Status = CheckStatus.Unknown;
            subControlResult.EvaluatedAt = DateTime.UtcNow;

            return new SubControlEvaluationSummary(
                aggregatedStatus: CheckStatus.Unknown,
                aggregatedReason: noEvidenceResult.Reason,
                perEvidenceResults: new List<EvaluationResult> { noEvidenceResult });
        }

        // Evaluate each Evidence item
        var perEvidenceResults = new List<EvaluationResult>(evidenceItems.Count);

        foreach (var evidence in evidenceItems)
        {
            var result = _typedEvidenceEvaluator.Evaluate(
                evidence,
                expectedValueString,
                expectedType,
                op);

            // Propagate result back to Evidence entity for audit/UI consumption
            evidence.Evaluation = result.Status;
            evidence.EvaluationReason = result.Reason;

            perEvidenceResults.Add(result);
        }

        // Aggregate per-Evidence results into SubControl-level status
        var aggregatedStatus = AggregateStatuses(perEvidenceResults);
        var aggregatedReason = BuildAggregatedReason(perEvidenceResults, aggregatedStatus);

        // Update SubControlResult in place
        subControlResult.Status = aggregatedStatus;
        subControlResult.EvaluatedAt = DateTime.UtcNow;

        return new SubControlEvaluationSummary(
            aggregatedStatus: aggregatedStatus,
            aggregatedReason: aggregatedReason,
            perEvidenceResults: perEvidenceResults);
    }

    /// <summary>
    /// Aggregates per-Evidence EvaluationResults into a single SubControl CheckStatus.
    /// 
    /// Precedence (highest to lowest):
    ///   Error > Unknown > Fail > Pass
    /// 
    /// This matches the contract defined in the Final Engineering Specification (Section 2.5):
    ///   Required ERROR > Required UNKNOWN > Required FAIL > Required PASS
    /// 
    /// The SubControl does not know Required/Optional (that is a Parent-level concern),
    /// so we apply raw precedence here. Parent aggregation (Phase 13) will apply the
    /// Required/Optional policy on top.
    /// </summary>
    private static CheckStatus AggregateStatuses(IReadOnlyList<EvaluationResult> results)
    {
        if (results.Count == 0)
            return CheckStatus.Unknown;

        if (results.Any(r => r.Status == CheckStatus.Error))
            return CheckStatus.Error;

        if (results.Any(r => r.Status == CheckStatus.Unknown))
            return CheckStatus.Unknown;

        if (results.Any(r => r.Status == CheckStatus.Fail))
            return CheckStatus.Fail;

        if (results.All(r => r.Status == CheckStatus.Pass))
            return CheckStatus.Pass;

        // Defensive fallback — should not be reachable given EvaluationResult only produces
        // Pass/Fail/Error/Unknown. Returns Unknown to be conservative (never silent Pass).
        return CheckStatus.Unknown;
    }

    /// <summary>
    /// Builds a human-readable aggregated reason from the per-Evidence results.
    /// </summary>
    private static string BuildAggregatedReason(IReadOnlyList<EvaluationResult> results, CheckStatus aggregated)
    {
        var passCount = results.Count(r => r.Status == CheckStatus.Pass);
        var failCount = results.Count(r => r.Status == CheckStatus.Fail);
        var errorCount = results.Count(r => r.Status == CheckStatus.Error);
        var unknownCount = results.Count(r => r.Status == CheckStatus.Unknown);

        return $"SubControl verdict={aggregated} from {results.Count} evidence items " +
               $"(pass={passCount}, fail={failCount}, error={errorCount}, unknown={unknownCount}). " +
               $"First non-pass reason: {results.FirstOrDefault(r => r.Status != CheckStatus.Pass)?.Reason ?? "all passed"}";
    }
}

// =========================================================================
// Sub-Phase 7.5 — SubControl evaluation summary value object
// =========================================================================

/// <summary>
/// Immutable value object returned by ControlEvaluator.EvaluateSubControlTyped.
/// 
/// Contains:
///   - AggregatedStatus: the SubControl-level verdict (also applied to SubControlResult.Status)
///   - AggregatedReason: human-readable summary of the aggregation
///   - PerEvidenceResults: list of EvaluationResult for each Evidence item (for audit/UI)
/// 
/// Defined as a nested-free class next to ControlEvaluator to keep the evaluation
/// output type close to its producer. Could be moved to Domain/ValueObjects in a
/// future refactor if needed by other layers.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.5
/// </summary>
public sealed class SubControlEvaluationSummary
{
    public CheckStatus AggregatedStatus { get; }
    public string AggregatedReason { get; }
    public IReadOnlyList<EvaluationResult> PerEvidenceResults { get; }

    public SubControlEvaluationSummary(
        CheckStatus aggregatedStatus,
        string aggregatedReason,
        IReadOnlyList<EvaluationResult> perEvidenceResults)
    {
        AggregatedStatus = aggregatedStatus;
        AggregatedReason = aggregatedReason ?? string.Empty;
        PerEvidenceResults = perEvidenceResults
            ?? new List<EvaluationResult>().AsReadOnly();
    }

    public bool IsPass => AggregatedStatus == CheckStatus.Pass;
    public bool IsFail => AggregatedStatus == CheckStatus.Fail;
    public bool IsError => AggregatedStatus == CheckStatus.Error;
    public bool IsUnknown => AggregatedStatus == CheckStatus.Unknown;

    public override string ToString()
        => $"[{AggregatedStatus}] {AggregatedReason}";
}