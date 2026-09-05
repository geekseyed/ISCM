using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Long (long) values.
/// 
/// Handles: EvidenceValueType.Long
/// Supported operators: Equals, NotEquals, GreaterThan, GreaterOrEqual, LessThan, LessOrEqual
/// 
/// Note: int values can be promoted to long during comparison (handled in ComparisonEngine).
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class LongEvaluator : ITypeSpecificEvaluator<long>
{
    public string EvaluatorName => "LongEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Long };

    public EvaluationResult Compare(long actual, long expected, Operator op)
    {
        return TypedComparers.CompareLong(actual, expected, op);
    }
}