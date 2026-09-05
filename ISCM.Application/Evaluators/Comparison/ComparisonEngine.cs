using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Comparison;

/// <summary>
/// Dispatcher engine that routes typed comparisons to the correct primitive method.
/// 
/// This class:
///   1. Takes generic typed values (object) and EvidenceValueType
///   2. Casts to the correct CLR type based on valueType
///   3. Calls the appropriate TypedComparers method
///   4. Returns EvaluationResult
/// 
/// Design rules:
///   - NEVER silently convert incompatible types
///   - If cast fails, return Error (not Pass, not fallback)
///   - If valueType is Unknown, return Error
///   - All type conversions are explicit and auditable
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.2
/// </summary>
public static class ComparisonEngine
{
    /// <summary>
    /// Main entry point for typed comparison.
    /// Routes to the correct TypedComparers method based on valueType.
    /// </summary>
    /// <param name="actual">The actual typed value (from EvidenceValue.TypedValue).</param>
    /// <param name="expected">The expected typed value (parsed from catalog string).</param>
    /// <param name="op">The comparison operator.</param>
    /// <param name="valueType">The declared type from the catalog.</param>
    /// <returns>EvaluationResult with Pass/Fail/Error status.</returns>
    public static EvaluationResult Evaluate(
        object? actual,
        object? expected,
        Operator op,
        EvidenceValueType valueType)
    {
        if (actual == null || expected == null)
        {
            return EvaluationResult.Error(
                "Comparison requires non-null actual and expected values.",
                EvaluationResult.BuildDetails(
                    actual: actual?.ToString() ?? "(null)",
                    expected: expected?.ToString() ?? "(null)",
                    op: op,
                    valueType: valueType.ToString()
                ));
        }

        return valueType switch
        {
            EvidenceValueType.Integer => EvaluateInteger(actual, expected, op),
            EvidenceValueType.Long => EvaluateLong(actual, expected, op),
            EvidenceValueType.Boolean => EvaluateBoolean(actual, expected, op),
            EvidenceValueType.String => EvaluateString(actual, expected, op),
            EvidenceValueType.Duration => EvaluateDuration(actual, expected, op),
            EvidenceValueType.Size => EvaluateSize(actual, expected, op),
            EvidenceValueType.Enum => EvaluateEnum(actual, expected, op),
            EvidenceValueType.Collection => EvaluateCollection(actual, expected, op),
            EvidenceValueType.RegistryValue => EvaluateRegistryValue(actual, expected, op),
            EvidenceValueType.PolicyValue => EvaluatePolicyValue(actual, expected, op),

            EvidenceValueType.Unknown => EvaluationResult.Error(
                "Cannot evaluate Unknown valueType. Type must be declared in catalog.",
                EvaluationResult.BuildDetails(
                    actual: actual.ToString(),
                    expected: expected.ToString(),
                    op: op,
                    valueType: "Unknown"
                )),

            _ => EvaluationResult.Error(
                $"Unsupported valueType: {valueType}.",
                EvaluationResult.BuildDetails(
                    actual: actual.ToString(),
                    expected: expected.ToString(),
                    op: op,
                    valueType: valueType.ToString()
                ))
        };
    }

    private static EvaluationResult EvaluateInteger(object actual, object expected, Operator op)
    {
        if (actual is int actualInt && expected is int expectedInt)
        {
            return TypedComparers.CompareInteger(actualInt, expectedInt, op);
        }

        return EvaluationResult.Error(
            $"Integer comparison requires int values. Got actual={actual.GetType().Name}, expected={expected.GetType().Name}.",
            EvaluationResult.BuildDetails(
                actual: actual.ToString(),
                expected: expected.ToString(),
                op: op,
                valueType: "Integer"
            ));
    }

    private static EvaluationResult EvaluateLong(object actual, object expected, Operator op)
    {
        // Allow int to be promoted to long
        long actualLong = actual switch
        {
            long l => l,
            int i => i,
            _ => throw new InvalidOperationException($"Cannot convert {actual.GetType().Name} to long.")
        };

        long expectedLong = expected switch
        {
            long l => l,
            int i => i,
            _ => throw new InvalidOperationException($"Cannot convert {expected.GetType().Name} to long.")
        };

        try
        {
            return TypedComparers.CompareLong(actualLong, expectedLong, op);
        }
        catch (InvalidOperationException ex)
        {
            return EvaluationResult.Error(
                ex.Message,
                EvaluationResult.BuildDetails(
                    actual: actual.ToString(),
                    expected: expected.ToString(),
                    op: op,
                    valueType: "Long"
                ));
        }
    }

    private static EvaluationResult EvaluateBoolean(object actual, object expected, Operator op)
    {
        if (actual is bool actualBool && expected is bool expectedBool)
        {
            return TypedComparers.CompareBoolean(actualBool, expectedBool, op);
        }

        return EvaluationResult.Error(
            $"Boolean comparison requires bool values. Got actual={actual.GetType().Name}, expected={expected.GetType().Name}.",
            EvaluationResult.BuildDetails(
                actual: actual.ToString(),
                expected: expected.ToString(),
                op: op,
                valueType: "Boolean"
            ));
    }

    private static EvaluationResult EvaluateString(object actual, object expected, Operator op)
    {
        var actualStr = actual as string ?? actual.ToString();
        var expectedStr = expected as string ?? expected.ToString();

        return TypedComparers.CompareString(actualStr, expectedStr, op);
    }

    private static EvaluationResult EvaluateDuration(object actual, object expected, Operator op)
    {
        if (actual is TimeSpan actualTs && expected is TimeSpan expectedTs)
        {
            return TypedComparers.CompareDuration(actualTs, expectedTs, op);
        }

        return EvaluationResult.Error(
            $"Duration comparison requires TimeSpan values. Got actual={actual.GetType().Name}, expected={expected.GetType().Name}.",
            EvaluationResult.BuildDetails(
                actual: actual.ToString(),
                expected: expected.ToString(),
                op: op,
                valueType: "Duration"
            ));
    }

    private static EvaluationResult EvaluateSize(object actual, object expected, Operator op)
    {
        // Allow int/long for size (bytes)
        long actualBytes = actual switch
        {
            long l => l,
            int i => i,
            _ => throw new InvalidOperationException($"Cannot convert {actual.GetType().Name} to long (bytes).")
        };

        long expectedBytes = expected switch
        {
            long l => l,
            int i => i,
            _ => throw new InvalidOperationException($"Cannot convert {expected.GetType().Name} to long (bytes).")
        };

        try
        {
            return TypedComparers.CompareSize(actualBytes, expectedBytes, op);
        }
        catch (InvalidOperationException ex)
        {
            return EvaluationResult.Error(
                ex.Message,
                EvaluationResult.BuildDetails(
                    actual: actual.ToString(),
                    expected: expected.ToString(),
                    op: op,
                    valueType: "Size"
                ));
        }
    }

    private static EvaluationResult EvaluateEnum(object actual, object expected, Operator op)
    {
        return TypedComparers.CompareEnum(actual, expected, op);
    }

    private static EvaluationResult EvaluateCollection(object actual, object expected, Operator op)
    {
        if (actual is IReadOnlyCollection<object> actualColl && expected is IReadOnlyCollection<object> expectedColl)
        {
            return TypedComparers.CompareCollection(actualColl, expectedColl, op);
        }

        return EvaluationResult.Error(
            $"Collection comparison requires IReadOnlyCollection<object> values. Got actual={actual.GetType().Name}, expected={expected.GetType().Name}.",
            EvaluationResult.BuildDetails(
                actual: actual.ToString(),
                expected: expected.ToString(),
                op: op,
                valueType: "Collection"
            ));
    }

    private static EvaluationResult EvaluateRegistryValue(object actual, object expected, Operator op)
    {
        return TypedComparers.CompareRegistryValue(actual, expected, op);
    }

    private static EvaluationResult EvaluatePolicyValue(object actual, object expected, Operator op)
    {
        return TypedComparers.ComparePolicyValue(actual, expected, op);
    }
}