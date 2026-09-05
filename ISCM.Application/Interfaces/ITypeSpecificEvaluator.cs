using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Generic contract for type-specific evidence evaluators.
///
/// Each implementation handles one or more EvidenceValueType values
/// and performs comparisons on STRONGLY-TYPED values.
///
/// Design rules:
///   1. Implementations must NEVER fall back to string parsing.
///   2. If the input types are incompatible, they must return Error, not silently convert.
///   3. Each implementation declares which EvidenceValueType values it handles
///      via SupportedTypes, so the TypedEvidenceEvaluator dispatcher can route correctly.
///   4. The Compare method receives already-typed values; parsing from string
///      is the responsibility of the dispatcher (TypedEvidenceEvaluator / ComparisonEngine).
///
/// This interface is intentionally minimal: one method, one property set, one name.
/// Type-specific behavior (unit-aware duration, byte-aware size, case-insensitive string)
/// is encapsulated inside each implementation.
///
/// Phase 7 — Typed Evaluation
/// </summary>
public interface ITypeSpecificEvaluator<T>
{
    /// <summary>
    /// Compares two typed values with the specified operator.
    /// </summary>
    /// <param name="actual">The actual value from evidence (already typed, not null).</param>
    /// <param name="expected">The expected value (already typed, not null).</param>
    /// <param name="op">The comparison operator from the catalog.</param>
    /// <returns>
    /// EvaluationResult with Pass, Fail, or Error status.
    /// Never returns Unknown — if the inputs are valid, the comparison must produce Pass/Fail.
    /// </returns>
    EvaluationResult Compare(T actual, T expected, Operator op);

    /// <summary>
    /// The set of EvidenceValueType values this evaluator handles.
    /// Used by TypedEvidenceEvaluator to dispatch to the correct evaluator.
    /// Must contain at least one value.
    /// </summary>
    IReadOnlySet<EvidenceValueType> SupportedTypes { get; }

    /// <summary>
    /// Display name for diagnostics and logging.
    /// </summary>
    string EvaluatorName { get; }
}