using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for PolicyValue values.
/// 
/// Handles: EvidenceValueType.PolicyValue
/// Supported operators: Equals, NotEquals
/// 
/// Compares security policy values (from secedit, net accounts, auditpol, etc.)
/// by their string representation (case-insensitive).
/// The actual CLR type can vary, so object is used as generic parameter.
/// The dispatcher routes based on SupportedTypes (EvidenceValueType.PolicyValue).
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class PolicyValueEvaluator : ITypeSpecificEvaluator<object>
{
    public string EvaluatorName => "PolicyValueEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.PolicyValue };

    public EvaluationResult Compare(object actual, object expected, Operator op)
    {
        return TypedComparers.ComparePolicyValue(actual, expected, op);
    }
}