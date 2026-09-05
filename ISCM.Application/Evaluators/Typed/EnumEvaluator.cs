using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Enum values.
/// 
/// Handles: EvidenceValueType.Enum
/// Supported operators: Equals, NotEquals (case-insensitive name comparison)
/// 
/// Uses object as the generic type parameter because different enums have different
/// CLR types. The dispatcher (TypedEvidenceEvaluator) routes based on SupportedTypes.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class EnumEvaluator : ITypeSpecificEvaluator<object>
{
    public string EvaluatorName => "EnumEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Enum };

    public EvaluationResult Compare(object actual, object expected, Operator op)
    {
        return TypedComparers.CompareEnum(actual, expected, op);
    }
}