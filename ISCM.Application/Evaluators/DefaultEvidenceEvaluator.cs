using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;

namespace ISCM.Application.Evaluators;

/// <summary>
/// Default implementation of IEvidenceEvaluator.
/// Supports various comparison rules: ==, !=, >=, <=, >, <, Contains, StartsWith, EndsWith
/// </summary>
public class DefaultEvidenceEvaluator : IEvidenceEvaluator
{
    public (CheckStatus Status, string Reason) Evaluate(string parsedValue, string expectedValue, string? evaluationRule = null)
    {
        if (string.IsNullOrWhiteSpace(parsedValue))
        {
            return (CheckStatus.Unknown, "No value was parsed from the evidence source.");
        }

        if (string.IsNullOrWhiteSpace(expectedValue))
        {
            return (CheckStatus.Unknown, "No expected value was defined for this control.");
        }

        // Normalize values for comparison
        var normalizedParsed = parsedValue.Trim();
        var normalizedExpected = expectedValue.Trim();

        // Determine the rule to use
        var rule = evaluationRule ?? DetectRule(normalizedExpected);

        switch (rule.ToUpperInvariant())
        {
            case "==":
            case "EQUALS":
            case "EXACT":
                return EvaluateEquals(normalizedParsed, normalizedExpected);

            case "!=":
            case "NOT_EQUALS":
                return EvaluateNotEquals(normalizedParsed, normalizedExpected);

            case ">=":
            case "GREATER_OR_EQUAL":
                return EvaluateGreaterOrEqual(normalizedParsed, normalizedExpected);

            case "<=":
            case "LESS_OR_EQUAL":
                return EvaluateLessOrEqual(normalizedParsed, normalizedExpected);

            case ">":
            case "GREATER":
                return EvaluateGreater(normalizedParsed, normalizedExpected);

            case "<":
            case "LESS":
                return EvaluateLess(normalizedParsed, normalizedExpected);

            case "CONTAINS":
                return EvaluateContains(normalizedParsed, normalizedExpected);

            case "STARTSWITH":
                return EvaluateStartsWith(normalizedParsed, normalizedExpected);

            case "ENDSWITH":
                return EvaluateEndsWith(normalizedParsed, normalizedExpected);

            case "BOOLEAN_TRUE":
            case "TRUE":
                return EvaluateBooleanTrue(normalizedParsed);

            case "BOOLEAN_FALSE":
            case "FALSE":
                return EvaluateBooleanFalse(normalizedParsed);

            default:
                // Default to exact match
                return EvaluateEquals(normalizedParsed, normalizedExpected);
        }
    }

    private string DetectRule(string expectedValue)
    {
        // If expected value contains comparison operators, extract the rule
        if (expectedValue.StartsWith(">=")) return ">=";
        if (expectedValue.StartsWith("<=")) return "<=";
        if (expectedValue.StartsWith(">")) return ">";
        if (expectedValue.StartsWith("<")) return "<";
        if (expectedValue.StartsWith("!=")) return "!=";
        if (expectedValue.Equals("True", StringComparison.OrdinalIgnoreCase)) return "BOOLEAN_TRUE";
        if (expectedValue.Equals("False", StringComparison.OrdinalIgnoreCase)) return "BOOLEAN_FALSE";

        return "==";
    }

    private (CheckStatus Status, string Reason) EvaluateEquals(string parsed, string expected)
    {
        var passed = string.Equals(parsed, expected, StringComparison.OrdinalIgnoreCase);
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' matches expected '{expected}'." : $"Value '{parsed}' does not match expected '{expected}'."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateNotEquals(string parsed, string expected)
    {
        var passed = !string.Equals(parsed, expected, StringComparison.OrdinalIgnoreCase);
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' is different from '{expected}' as required." : $"Value '{parsed}' should not be '{expected}'."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateGreaterOrEqual(string parsed, string expected)
    {
        if (int.TryParse(parsed, out int parsedInt) && int.TryParse(expected, out int expectedInt))
        {
            var passed = parsedInt >= expectedInt;
            return (
                passed ? CheckStatus.Pass : CheckStatus.Fail,
                passed ? $"Value {parsedInt} >= {expectedInt} as required." : $"Value {parsedInt} is less than required {expectedInt}."
            );
        }
        return (CheckStatus.Error, $"Cannot compare '{parsed}' and '{expected}' as integers.");
    }

    private (CheckStatus Status, string Reason) EvaluateLessOrEqual(string parsed, string expected)
    {
        if (int.TryParse(parsed, out int parsedInt) && int.TryParse(expected, out int expectedInt))
        {
            var passed = parsedInt <= expectedInt;
            return (
                passed ? CheckStatus.Pass : CheckStatus.Fail,
                passed ? $"Value {parsedInt} <= {expectedInt} as required." : $"Value {parsedInt} is greater than required {expectedInt}."
            );
        }
        return (CheckStatus.Error, $"Cannot compare '{parsed}' and '{expected}' as integers.");
    }

    private (CheckStatus Status, string Reason) EvaluateGreater(string parsed, string expected)
    {
        if (int.TryParse(parsed, out int parsedInt) && int.TryParse(expected, out int expectedInt))
        {
            var passed = parsedInt > expectedInt;
            return (
                passed ? CheckStatus.Pass : CheckStatus.Fail,
                passed ? $"Value {parsedInt} > {expectedInt} as required." : $"Value {parsedInt} is not greater than {expectedInt}."
            );
        }
        return (CheckStatus.Error, $"Cannot compare '{parsed}' and '{expected}' as integers.");
    }

    private (CheckStatus Status, string Reason) EvaluateLess(string parsed, string expected)
    {
        if (int.TryParse(parsed, out int parsedInt) && int.TryParse(expected, out int expectedInt))
        {
            var passed = parsedInt < expectedInt;
            return (
                passed ? CheckStatus.Pass : CheckStatus.Fail,
                passed ? $"Value {parsedInt} < {expectedInt} as required." : $"Value {parsedInt} is not less than {expectedInt}."
            );
        }
        return (CheckStatus.Error, $"Cannot compare '{parsed}' and '{expected}' as integers.");
    }

    private (CheckStatus Status, string Reason) EvaluateContains(string parsed, string expected)
    {
        var passed = parsed.Contains(expected, StringComparison.OrdinalIgnoreCase);
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' contains '{expected}'." : $"Value '{parsed}' does not contain '{expected}'."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateStartsWith(string parsed, string expected)
    {
        var passed = parsed.StartsWith(expected, StringComparison.OrdinalIgnoreCase);
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' starts with '{expected}'." : $"Value '{parsed}' does not start with '{expected}'."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateEndsWith(string parsed, string expected)
    {
        var passed = parsed.EndsWith(expected, StringComparison.OrdinalIgnoreCase);
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' ends with '{expected}'." : $"Value '{parsed}' does not end with '{expected}'."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateBooleanTrue(string parsed)
    {
        var passed = parsed.Equals("True", StringComparison.OrdinalIgnoreCase) || parsed == "1";
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' is True as required." : $"Value '{parsed}' is not True."
        );
    }

    private (CheckStatus Status, string Reason) EvaluateBooleanFalse(string parsed)
    {
        var passed = parsed.Equals("False", StringComparison.OrdinalIgnoreCase) || parsed == "0";
        return (
            passed ? CheckStatus.Pass : CheckStatus.Fail,
            passed ? $"Value '{parsed}' is False as required." : $"Value '{parsed}' is not False."
        );
    }
}