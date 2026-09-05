using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace ISCM.Application.Services;

/// <summary>
/// Parses catalog-declared expected value strings into typed CLR objects.
/// 
/// This is the bridge between the catalog's string representation of expected values
/// (e.g., "14 characters", "60 days", "Enabled") and the strongly-typed values
/// that ITypeSpecificEvaluator implementations need for comparison.
/// 
/// Design rules:
///   1. NEVER silently return a default value on parse failure.
///   2. Always return ParseResult with Success / Invalid / Error state.
///   3. Unit extraction is explicit (number + unit are separated).
///   4. Case-insensitive matching for boolean/enum keywords.
///   5. Invariant culture is used for numeric parsing to avoid locale issues.
/// 
/// Supported conversions:
///   "14 characters"        → Integer(14) or Duration(14 days) depending on context
///   "60 days"              → TimeSpan.FromDays(60)
///   "15 minutes"           → TimeSpan.FromMinutes(15)
///   "Enabled" / "Disabled" → bool
///   "True" / "False"       → bool
///   "1 MB"                 → 1048576 (bytes)
///   "value1, value2"       → List&lt;object&gt; for Collection
///   any string             → string (String, Enum, RegistryValue, PolicyValue)
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.4
/// </summary>
public sealed class ExpectedValueParser
{
    // Regex to extract leading number from strings like "14 characters", "60 days"
    private static readonly Regex LeadingNumberRegex = new(
        @"^\s*(-?\d+(?:\.\d+)?)\s*(.*)$",
        RegexOptions.Compiled);

    private static readonly Regex SizeRegex = new(
        @"^\s*(-?\d+(?:\.\d+)?)\s*(bytes?|kb|mb|gb|tb)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Parses a catalog expected-value string into a typed object based on declared type.
    /// </summary>
    /// <param name="expectedValueString">The raw string from the catalog (e.g., "14 characters").</param>
    /// <param name="expectedType">The declared type from the catalog.</param>
    /// <returns>ParseResult&lt;object&gt; with typed value on Success, error info otherwise.</returns>
    public ParseResult<object> Parse(string expectedValueString, ExpectedValueType expectedType)
    {
        if (string.IsNullOrWhiteSpace(expectedValueString))
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                "Expected value string is null or whitespace.",
                expectedValueString ?? "(null)");
        }

        return expectedType switch
        {
            ExpectedValueType.Integer => ParseInteger(expectedValueString),
            ExpectedValueType.Boolean => ParseBoolean(expectedValueString),
            ExpectedValueType.Duration => ParseDuration(expectedValueString),
            ExpectedValueType.String => ParseResult<object>.Success((object)expectedValueString.Trim()),
            ExpectedValueType.Enum => ParseResult<object>.Success((object)expectedValueString.Trim()),
            ExpectedValueType.RegistryValue => ParseResult<object>.Success((object)expectedValueString.Trim()),
            ExpectedValueType.PolicyValue => ParseResult<object>.Success((object)expectedValueString.Trim()),
            ExpectedValueType.Collection => ParseCollection(expectedValueString),

            // Size, Long handled separately if needed; default to string for now
            _ => ParseResult<object>.Failure(
                ParseErrorCode.TypeMismatch,
                $"Unsupported ExpectedValueType: {expectedType}.",
                expectedValueString)
        };
    }

    // ==========================================================================
    // Integer: "14", "14 characters", "5 invalid logon attempts" → 14
    // ==========================================================================

    private ParseResult<object> ParseInteger(string input)
    {
        // Direct int parse first
        if (int.TryParse(input.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var directInt))
        {
            return ParseResult<object>.Success((object)directInt);
        }

        // Extract leading number
        var match = LeadingNumberRegex.Match(input);
        if (!match.Success)
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Cannot parse integer from '{input}'. No leading number found.",
                input);
        }

        if (!int.TryParse(match.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var extractedInt))
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Extracted number '{match.Groups[1].Value}' is not a valid integer.",
                input);
        }

        return ParseResult<object>.Success((object)extractedInt);
    }

    // ==========================================================================
    // Boolean: "Enabled"/"Disabled", "True"/"False", "1"/"0", "Yes"/"No"
    // ==========================================================================

    private ParseResult<object> ParseBoolean(string input)
    {
        var normalized = input.Trim();

        // Direct bool parse
        if (bool.TryParse(normalized, out var directBool))
        {
            return ParseResult<object>.Success((object)directBool);
        }

        // Keyword matching (case-insensitive)
        var upper = normalized.ToUpperInvariant();

        if (upper is "ENABLED" or "TRUE" or "YES" or "ON" or "1")
            return ParseResult<object>.Success((object)true);

        if (upper is "DISABLED" or "FALSE" or "NO" or "OFF" or "0")
            return ParseResult<object>.Success((object)false);

        return ParseResult<object>.Failure(
            ParseErrorCode.InvalidFormat,
            $"Cannot parse boolean from '{input}'. Expected: Enabled/Disabled, True/False, Yes/No, 1/0.",
            input);
    }

    // ==========================================================================
    // Duration: "60 days", "15 minutes", "2 hours", "30 seconds" → TimeSpan
    // ==========================================================================

    private ParseResult<object> ParseDuration(string input)
    {
        var match = LeadingNumberRegex.Match(input);
        if (!match.Success)
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Cannot parse duration from '{input}'. Expected format: '<number> <unit>'.",
                input);
        }

        if (!double.TryParse(match.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number))
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Extracted number '{match.Groups[1].Value}' is not a valid number.",
                input);
        }

        var unit = match.Groups[2].Value.Trim().ToLowerInvariant();

        TimeSpan ts;
        try
        {
            ts = unit switch
            {
                "day" or "days" or "d" => TimeSpan.FromDays(number),
                "hour" or "hours" or "h" or "hr" or "hrs" => TimeSpan.FromHours(number),
                "minute" or "minutes" or "min" or "mins" or "m" => TimeSpan.FromMinutes(number),
                "second" or "seconds" or "sec" or "secs" or "s" => TimeSpan.FromSeconds(number),
                "millisecond" or "milliseconds" or "ms" => TimeSpan.FromMilliseconds(number),
                "" => TimeSpan.FromDays(number), // default to days if no unit (backward compat)
                _ => throw new InvalidOperationException($"Unknown duration unit: '{unit}'.")
            };
        }
        catch (InvalidOperationException ex)
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                ex.Message,
                input);
        }

        return ParseResult<object>.Success((object)ts);
    }

    // ==========================================================================
    // Collection: "value1, value2, value3" → List<object>
    // ==========================================================================

    private ParseResult<object> ParseCollection(string input)
    {
        var items = input
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => (object)s)
            .ToList();

        if (items.Count == 0)
        {
            return ParseResult<object>.Failure(
                ParseErrorCode.InvalidFormat,
                "Collection string is empty after splitting.",
                input);
        }

        return ParseResult<object>.Success((object)items);
    }

    // ==========================================================================
    // Size: "1024 bytes", "1 KB", "1 MB" → long (bytes)
    // ==========================================================================

    /// <summary>
    /// Parses a size string with unit into bytes.
    /// Called explicitly when Size type is used; kept separate from main Parse switch.
    /// </summary>
    public ParseResult<long> ParseSize(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return ParseResult<long>.Failure(
                ParseErrorCode.InvalidFormat,
                "Size string is null or whitespace.",
                input ?? "(null)");
        }

        // Direct long parse (plain number = bytes)
        if (long.TryParse(input.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var directBytes))
        {
            return ParseResult<long>.Success(directBytes);
        }

        var match = SizeRegex.Match(input);
        if (!match.Success)
        {
            return ParseResult<long>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Cannot parse size from '{input}'. Expected format: '<number> <unit>' where unit is bytes/KB/MB/GB/TB.",
                input);
        }

        if (!double.TryParse(match.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number))
        {
            return ParseResult<long>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Extracted number '{match.Groups[1].Value}' is not valid.",
                input);
        }

        var unit = match.Groups[2].Value.ToLowerInvariant();
        long bytes = unit switch
        {
            "byte" or "bytes" => (long)number,
            "kb" => (long)(number * 1024L),
            "mb" => (long)(number * 1024L * 1024L),
            "gb" => (long)(number * 1024L * 1024L * 1024L),
            "tb" => (long)(number * 1024L * 1024L * 1024L * 1024L),
            _ => throw new InvalidOperationException($"Unknown size unit: '{unit}'.")
        };

        return ParseResult<long>.Success(bytes);
    }

    /// <summary>
    /// Parses a long value. Handles direct number or number with suffix.
    /// </summary>
    public ParseResult<long> ParseLong(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return ParseResult<long>.Failure(
                ParseErrorCode.InvalidFormat,
                "Long string is null or whitespace.",
                input ?? "(null)");
        }

        if (long.TryParse(input.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var direct))
        {
            return ParseResult<long>.Success(direct);
        }

        var match = LeadingNumberRegex.Match(input);
        if (!match.Success ||
            !long.TryParse(match.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var extracted))
        {
            return ParseResult<long>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Cannot parse long from '{input}'.",
                input);
        }

        return ParseResult<long>.Success(extracted);
    }
}