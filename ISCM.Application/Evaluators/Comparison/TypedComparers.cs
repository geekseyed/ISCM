using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Evaluators.Comparison;

/// <summary>
/// Static class containing all typed comparison primitives.
/// 
/// Each method:
///   1. Takes strongly-typed inputs (no string parsing here)
///   2. Applies the specified Operator
///   3. Returns EvaluationResult with Pass/Fail/Error
///   4. Populates Details dictionary with consistent keys for audit/UI
/// 
/// Design rules:
///   - NEVER silently convert incompatible types
///   - NEVER return Unknown for valid inputs (only Error if operator is unsupported)
///   - Always use EvaluationResult.BuildDetails() for consistency
///   - Unit-aware for Duration/Size where applicable
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.2
/// </summary>
public static class TypedComparers
{
    // ========================================================================
    // Integer Comparison
    // ========================================================================

    public static EvaluationResult CompareInteger(int actual, int expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual.ToString(),
            expected: expected.ToString(),
            op: op,
            valueType: "Integer"
        );

        return op switch
        {
            Operator.Equals => actual == expected
                ? EvaluationResult.Pass($"Integer {actual} equals {expected}.", details)
                : EvaluationResult.Fail($"Integer {actual} does not equal {expected}.", details),

            Operator.NotEquals => actual != expected
                ? EvaluationResult.Pass($"Integer {actual} is not equal to {expected} as required.", details)
                : EvaluationResult.Fail($"Integer {actual} equals {expected}, which violates NotEquals.", details),

            Operator.GreaterThan => actual > expected
                ? EvaluationResult.Pass($"Integer {actual} > {expected}.", details)
                : EvaluationResult.Fail($"Integer {actual} is not greater than {expected}.", details),

            Operator.GreaterOrEqual => actual >= expected
                ? EvaluationResult.Pass($"Integer {actual} >= {expected}.", details)
                : EvaluationResult.Fail($"Integer {actual} is less than {expected}.", details),

            Operator.LessThan => actual < expected
                ? EvaluationResult.Pass($"Integer {actual} < {expected}.", details)
                : EvaluationResult.Fail($"Integer {actual} is not less than {expected}.", details),

            Operator.LessOrEqual => actual <= expected
                ? EvaluationResult.Pass($"Integer {actual} <= {expected}.", details)
                : EvaluationResult.Fail($"Integer {actual} is greater than {expected}.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Integer comparison.",
                details)
        };
    }

    // ========================================================================
    // Long Comparison
    // ========================================================================

    public static EvaluationResult CompareLong(long actual, long expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual.ToString(),
            expected: expected.ToString(),
            op: op,
            valueType: "Long"
        );

        return op switch
        {
            Operator.Equals => actual == expected
                ? EvaluationResult.Pass($"Long {actual} equals {expected}.", details)
                : EvaluationResult.Fail($"Long {actual} does not equal {expected}.", details),

            Operator.NotEquals => actual != expected
                ? EvaluationResult.Pass($"Long {actual} is not equal to {expected} as required.", details)
                : EvaluationResult.Fail($"Long {actual} equals {expected}, which violates NotEquals.", details),

            Operator.GreaterThan => actual > expected
                ? EvaluationResult.Pass($"Long {actual} > {expected}.", details)
                : EvaluationResult.Fail($"Long {actual} is not greater than {expected}.", details),

            Operator.GreaterOrEqual => actual >= expected
                ? EvaluationResult.Pass($"Long {actual} >= {expected}.", details)
                : EvaluationResult.Fail($"Long {actual} is less than {expected}.", details),

            Operator.LessThan => actual < expected
                ? EvaluationResult.Pass($"Long {actual} < {expected}.", details)
                : EvaluationResult.Fail($"Long {actual} is not less than {expected}.", details),

            Operator.LessOrEqual => actual <= expected
                ? EvaluationResult.Pass($"Long {actual} <= {expected}.", details)
                : EvaluationResult.Fail($"Long {actual} is greater than {expected}.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Long comparison.",
                details)
        };
    }

    // ========================================================================
    // Boolean Comparison
    // ========================================================================

    public static EvaluationResult CompareBoolean(bool actual, bool expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual.ToString(),
            expected: expected.ToString(),
            op: op,
            valueType: "Boolean"
        );

        return op switch
        {
            Operator.Equals => actual == expected
                ? EvaluationResult.Pass($"Boolean {actual} equals {expected}.", details)
                : EvaluationResult.Fail($"Boolean {actual} does not equal {expected}.", details),

            Operator.NotEquals => actual != expected
                ? EvaluationResult.Pass($"Boolean {actual} is not equal to {expected} as required.", details)
                : EvaluationResult.Fail($"Boolean {actual} equals {expected}, which violates NotEquals.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Boolean comparison. Only Equals/NotEquals are valid.",
                details)
        };
    }

    // ========================================================================
    // String Comparison (case-insensitive by default)
    // ========================================================================

    public static EvaluationResult CompareString(string actual, string expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual,
            expected: expected,
            op: op,
            valueType: "String"
        );

        return op switch
        {
            Operator.Equals => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"String '{actual}' equals '{expected}' (case-insensitive).", details)
                : EvaluationResult.Fail($"String '{actual}' does not equal '{expected}'.", details),

            Operator.NotEquals => !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"String '{actual}' is not equal to '{expected}' as required.", details)
                : EvaluationResult.Fail($"String '{actual}' equals '{expected}', which violates NotEquals.", details),

            Operator.Contains => actual.Contains(expected, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"String '{actual}' contains '{expected}'.", details)
                : EvaluationResult.Fail($"String '{actual}' does not contain '{expected}'.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for String comparison. Supported: Equals, NotEquals, Contains.",
                details)
        };
    }

    // ========================================================================
    // Duration Comparison (TimeSpan, unit-aware)
    // ========================================================================

    public static EvaluationResult CompareDuration(TimeSpan actual, TimeSpan expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: FormatDuration(actual),
            expected: FormatDuration(expected),
            op: op,
            valueType: "Duration",
            unit: "TimeSpan"
        );

        return op switch
        {
            Operator.Equals => actual == expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} equals {FormatDuration(expected)}.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} does not equal {FormatDuration(expected)}.", details),

            Operator.NotEquals => actual != expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} is not equal to {FormatDuration(expected)} as required.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} equals {FormatDuration(expected)}, which violates NotEquals.", details),

            Operator.GreaterThan => actual > expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} > {FormatDuration(expected)}.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} is not greater than {FormatDuration(expected)}.", details),

            Operator.GreaterOrEqual => actual >= expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} >= {FormatDuration(expected)}.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} is less than {FormatDuration(expected)}.", details),

            Operator.LessThan => actual < expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} < {FormatDuration(expected)}.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} is not less than {FormatDuration(expected)}.", details),

            Operator.LessOrEqual => actual <= expected
                ? EvaluationResult.Pass($"Duration {FormatDuration(actual)} <= {FormatDuration(expected)}.", details)
                : EvaluationResult.Fail($"Duration {FormatDuration(actual)} is greater than {FormatDuration(expected)}.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Duration comparison.",
                details)
        };
    }

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalDays >= 1)
            return $"{ts.TotalDays:F2} days";
        if (ts.TotalHours >= 1)
            return $"{ts.TotalHours:F2} hours";
        if (ts.TotalMinutes >= 1)
            return $"{ts.TotalMinutes:F2} minutes";
        return $"{ts.TotalSeconds:F2} seconds";
    }

    // ========================================================================
    // Size Comparison (bytes, byte-aware)
    // ========================================================================

    public static EvaluationResult CompareSize(long actualBytes, long expectedBytes, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: FormatSize(actualBytes),
            expected: FormatSize(expectedBytes),
            op: op,
            valueType: "Size",
            unit: "bytes"
        );

        return op switch
        {
            Operator.Equals => actualBytes == expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} equals {FormatSize(expectedBytes)}.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} does not equal {FormatSize(expectedBytes)}.", details),

            Operator.NotEquals => actualBytes != expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} is not equal to {FormatSize(expectedBytes)} as required.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} equals {FormatSize(expectedBytes)}, which violates NotEquals.", details),

            Operator.GreaterThan => actualBytes > expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} > {FormatSize(expectedBytes)}.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} is not greater than {FormatSize(expectedBytes)}.", details),

            Operator.GreaterOrEqual => actualBytes >= expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} >= {FormatSize(expectedBytes)}.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} is less than {FormatSize(expectedBytes)}.", details),

            Operator.LessThan => actualBytes < expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} < {FormatSize(expectedBytes)}.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} is not less than {FormatSize(expectedBytes)}.", details),

            Operator.LessOrEqual => actualBytes <= expectedBytes
                ? EvaluationResult.Pass($"Size {FormatSize(actualBytes)} <= {FormatSize(expectedBytes)}.", details)
                : EvaluationResult.Fail($"Size {FormatSize(actualBytes)} is greater than {FormatSize(expectedBytes)}.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Size comparison.",
                details)
        };
    }

    private static string FormatSize(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024)
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        if (bytes >= 1024 * 1024)
            return $"{bytes / (1024.0 * 1024):F2} MB";
        if (bytes >= 1024)
            return $"{bytes / 1024.0:F2} KB";
        return $"{bytes} bytes";
    }

    // ========================================================================
    // Enum Comparison (safe enum compare)
    // ========================================================================

    public static EvaluationResult CompareEnum(object actual, object expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual?.ToString() ?? "(null)",
            expected: expected?.ToString() ?? "(null)",
            op: op,
            valueType: "Enum"
        );

        if (actual == null || expected == null)
        {
            return EvaluationResult.Error(
                "Enum comparison requires non-null actual and expected values.",
                details);
        }

        // Convert to string for comparison (enum names are case-insensitive)
        var actualStr = actual.ToString();
        var expectedStr = expected.ToString();

        return op switch
        {
            Operator.Equals => string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Enum {actualStr} equals {expectedStr}.", details)
                : EvaluationResult.Fail($"Enum {actualStr} does not equal {expectedStr}.", details),

            Operator.NotEquals => !string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Enum {actualStr} is not equal to {expectedStr} as required.", details)
                : EvaluationResult.Fail($"Enum {actualStr} equals {expectedStr}, which violates NotEquals.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Enum comparison. Only Equals/NotEquals are valid.",
                details)
        };
    }

    // ========================================================================
    // Collection Comparison (SetMembership)
    // ========================================================================

    public static EvaluationResult CompareCollection(
        IReadOnlyCollection<object> actual,
        IReadOnlyCollection<object> expected,
        Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: $"[{string.Join(", ", actual.Select(x => x?.ToString() ?? "(null)"))}]",
            expected: $"[{string.Join(", ", expected.Select(x => x?.ToString() ?? "(null)"))}]",
            op: op,
            valueType: "Collection"
        );

        return op switch
        {
            Operator.Equals => CollectionsEqual(actual, expected)
                ? EvaluationResult.Pass("Collections are equal.", details)
                : EvaluationResult.Fail("Collections are not equal.", details),

            Operator.NotEquals => !CollectionsEqual(actual, expected)
                ? EvaluationResult.Pass("Collections are not equal as required.", details)
                : EvaluationResult.Fail("Collections are equal, which violates NotEquals.", details),

            Operator.SetMembership => SetMembershipCheck(actual, expected)
                ? EvaluationResult.Pass("All expected items are present in actual collection.", details)
                : EvaluationResult.Fail("Some expected items are missing from actual collection.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for Collection comparison. Supported: Equals, NotEquals, SetMembership.",
                details)
        };
    }

    private static bool CollectionsEqual(IReadOnlyCollection<object> actual, IReadOnlyCollection<object> expected)
    {
        if (actual.Count != expected.Count)
            return false;

        var actualSet = new HashSet<string>(actual.Select(x => x?.ToString() ?? "(null)"), StringComparer.OrdinalIgnoreCase);
        var expectedSet = new HashSet<string>(expected.Select(x => x?.ToString() ?? "(null)"), StringComparer.OrdinalIgnoreCase);

        return actualSet.SetEquals(expectedSet);
    }

    private static bool SetMembershipCheck(IReadOnlyCollection<object> actual, IReadOnlyCollection<object> expected)
    {
        var actualSet = new HashSet<string>(actual.Select(x => x?.ToString() ?? "(null)"), StringComparer.OrdinalIgnoreCase);
        return expected.All(exp => actualSet.Contains(exp?.ToString() ?? "(null)"));
    }

    // ========================================================================
    // RegistryValue Comparison (specialized)
    // ========================================================================

    public static EvaluationResult CompareRegistryValue(object actual, object expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual?.ToString() ?? "(null)",
            expected: expected?.ToString() ?? "(null)",
            op: op,
            valueType: "RegistryValue"
        );

        // For RegistryValue, we compare string representations
        var actualStr = actual?.ToString() ?? string.Empty;
        var expectedStr = expected?.ToString() ?? string.Empty;

        return op switch
        {
            Operator.Equals => string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Registry value '{actualStr}' equals '{expectedStr}'.", details)
                : EvaluationResult.Fail($"Registry value '{actualStr}' does not equal '{expectedStr}'.", details),

            Operator.NotEquals => !string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Registry value '{actualStr}' is not equal to '{expectedStr}' as required.", details)
                : EvaluationResult.Fail($"Registry value '{actualStr}' equals '{expectedStr}', which violates NotEquals.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for RegistryValue comparison. Only Equals/NotEquals are valid.",
                details)
        };
    }

    // ========================================================================
    // PolicyValue Comparison (specialized)
    // ========================================================================

    public static EvaluationResult ComparePolicyValue(object actual, object expected, Operator op)
    {
        var details = EvaluationResult.BuildDetails(
            actual: actual?.ToString() ?? "(null)",
            expected: expected?.ToString() ?? "(null)",
            op: op,
            valueType: "PolicyValue"
        );

        // For PolicyValue, we compare string representations
        var actualStr = actual?.ToString() ?? string.Empty;
        var expectedStr = expected?.ToString() ?? string.Empty;

        return op switch
        {
            Operator.Equals => string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Policy value '{actualStr}' equals '{expectedStr}'.", details)
                : EvaluationResult.Fail($"Policy value '{actualStr}' does not equal '{expectedStr}'.", details),

            Operator.NotEquals => !string.Equals(actualStr, expectedStr, StringComparison.OrdinalIgnoreCase)
                ? EvaluationResult.Pass($"Policy value '{actualStr}' is not equal to '{expectedStr}' as required.", details)
                : EvaluationResult.Fail($"Policy value '{actualStr}' equals '{expectedStr}', which violates NotEquals.", details),

            _ => EvaluationResult.Error(
                $"Operator {op} is not supported for PolicyValue comparison. Only Equals/NotEquals are valid.",
                details)
        };
    }
}