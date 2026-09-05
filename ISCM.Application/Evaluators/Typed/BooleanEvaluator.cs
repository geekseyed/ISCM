using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Boolean (bool) values.
/// 
/// Handles: EvidenceValueType.Boolean
/// Supported operators: Equals, NotEquals (only logical comparisons for booleans)
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class BooleanEvaluator : ITypeSpecificEvaluator<bool>
{
    public string EvaluatorName => "BooleanEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Boolean };

    public EvaluationResult Compare(bool actual, bool expected, Operator op)
    {
        return TypedComparers.CompareBoolean(actual, expected, op);
    }
}