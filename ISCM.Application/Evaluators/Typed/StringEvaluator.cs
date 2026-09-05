using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for String values.
/// 
/// Handles: EvidenceValueType.String
/// Supported operators: Equals, NotEquals, Contains (case-insensitive by default)
/// 
/// All comparisons are case-insensitive unless explicitly specified otherwise.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class StringEvaluator : ITypeSpecificEvaluator<string>
{
    public string EvaluatorName => "StringEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.String };

    public EvaluationResult Compare(string actual, string expected, Operator op)
    {
        return TypedComparers.CompareString(actual ?? string.Empty, expected ?? string.Empty, op);
    }
}