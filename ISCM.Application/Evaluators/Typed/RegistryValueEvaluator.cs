using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for RegistryValue values.
/// 
/// Handles: EvidenceValueType.RegistryValue
/// Supported operators: Equals, NotEquals
/// 
/// Compares registry values by their string representation (case-insensitive).
/// The actual CLR type can vary (int, long, string, bool) depending on registry
/// value type (DWORD, QWORD, SZ, etc.), so object is used as generic parameter.
/// The dispatcher routes based on SupportedTypes (EvidenceValueType.RegistryValue).
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class RegistryValueEvaluator : ITypeSpecificEvaluator<object>
{
    public string EvaluatorName => "RegistryValueEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.RegistryValue };

    public EvaluationResult Compare(object actual, object expected, Operator op)
    {
        return TypedComparers.CompareRegistryValue(actual, expected, op);
    }
}