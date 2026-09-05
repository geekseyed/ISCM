using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Collection (IReadOnlyCollection&lt;object&gt;) values.
/// 
/// Handles: EvidenceValueType.Collection
/// Supported operators: Equals, NotEquals, SetMembership
/// 
/// - Equals: collections have the same items (order-insensitive)
/// - NotEquals: collections have different items
/// - SetMembership: all expected items are present in actual collection
/// 
/// All comparisons are case-insensitive for string elements.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class CollectionEvaluator : ITypeSpecificEvaluator<IReadOnlyCollection<object>>
{
    public string EvaluatorName => "CollectionEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Collection };

    public EvaluationResult Compare(
        IReadOnlyCollection<object> actual,
        IReadOnlyCollection<object> expected,
        Operator op)
    {
        return TypedComparers.CompareCollection(actual, expected, op);
    }
}