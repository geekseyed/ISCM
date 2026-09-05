using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Size (bytes) values.
/// 
/// Handles: EvidenceValueType.Size
/// Supported operators: Equals, NotEquals, GreaterThan, GreaterOrEqual, LessThan, LessOrEqual
/// 
/// Internally all sizes are compared as long (bytes), but reason messages
/// format the size in the most readable unit (bytes/KB/MB/GB).
/// 
/// Note: shares the CLR type 'long' with LongEvaluator, but routing is based on
/// SupportedTypes (EvidenceValueType.Size) in the TypedEvidenceEvaluator dispatcher,
/// not the CLR type.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class SizeEvaluator : ITypeSpecificEvaluator<long>
{
    public string EvaluatorName => "SizeEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Size };

    public EvaluationResult Compare(long actual, long expected, Operator op)
    {
        return TypedComparers.CompareSize(actual, expected, op);
    }
}