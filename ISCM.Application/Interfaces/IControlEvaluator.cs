using ISCM.Application.Evaluators;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Evaluates SubControl results into control-level results and findings.
/// 
/// Phase 10.4: Added EvaluateSubControlTyped to the interface so the Scanner
/// can invoke the typed evaluation pipeline through the DI-registered
/// IControlEvaluator abstraction.
/// </summary>
public interface IControlEvaluator
{
    /// <summary>
    /// Aggregates SubControl results into a single ControlResult.
    /// </summary>
    ControlResult Evaluate(ControlDefinition controlDefinition, IEnumerable<SubControlResult> subControlResults);

    /// <summary>
    /// Builds a Finding from SubControl results.
    /// If checkId is provided, it is used as the Finding's CheckId so that
    /// multiple checks of the same control (UAC/LM/ADM) don't overwrite each other.
    /// </summary>
    Finding EvaluateFromSubControls(ControlDefinition controlDefinition, List<SubControlResult> subControlResults, string? checkId = null);

    /// <summary>
    /// Evaluates a control from existing findings (used by the Findings UI).
    /// </summary>
    ControlResult EvaluateFromFindings(ControlDefinition controlDefinition, IEnumerable<Finding> findings);

    /// <summary>
    /// Phase 7.5 / Phase 10.4: Evaluates a single SubControl using the typed
    /// evidence evaluator with catalog-declared type and operator metadata.
    /// 
    /// Contract:
    ///   - Each Evidence item is evaluated via ITypedEvidenceEvaluator
    ///   - Evidence.Evaluation and Evidence.EvaluationReason are updated in place
    ///   - SubControlResult.Status is updated with the aggregated verdict
    ///   - Precedence: Error > Unknown > Fail > Pass; no evidence → Unknown
    /// 
    /// Throws InvalidOperationException if the implementing evaluator was
    /// constructed without an ITypedEvidenceEvaluator.
    /// </summary>
    /// <param name="subControlResult">The SubControlResult to evaluate. Must have EvidenceItems.</param>
    /// <param name="expectedValueString">The expected value string from the catalog (e.g., "14 characters").</param>
    /// <param name="expectedType">The declared type from the catalog.</param>
    /// <param name="op">The declared operator from the catalog.</param>
    /// <returns>SubControlEvaluationSummary with aggregated status, reason, and per-evidence results.</returns>
    SubControlEvaluationSummary EvaluateSubControlTyped(
        SubControlResult subControlResult,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op);
}