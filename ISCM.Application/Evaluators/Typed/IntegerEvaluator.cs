using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Integer (int) values.
/// 
/// Handles: EvidenceValueType.Integer
/// Supported operators: Equals, NotEquals, GreaterThan, GreaterOrEqual, LessThan, LessOrEqual
/// 
/// Delegates actual comparison to TypedComparers.CompareInteger.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class IntegerEvaluator : ITypeSpecificEvaluator<int>
{
    public string EvaluatorName => "IntegerEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Integer };

    public EvaluationResult Compare(int actual, int expected, Operator op)
    {
        return TypedComparers.CompareInteger(actual, expected, op);
    }
}