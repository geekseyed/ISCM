using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses `net accounts` output into structured NetAccountsData.
/// 
/// Each setting is extracted as an individual key/value pair.
/// The complete command output is NEVER used as a single setting value (BUG-02).
/// 
/// Handles:
///   - "Key:   Value" lines
///   - Numeric values and "Never" / "Unlimited"
///   - CRLF / LF newlines, whitespace, BOM
///   - Trailing "The command completed successfully." line
/// 
/// MUST NOT silently convert malformed input into a valid default.
/// </summary>
public class NetAccountsParser : IParser<string, NetAccountsData>
{
    public string Name => "NetAccountsParser";
    public string Version => "1.0.0";

    public IEnumerable<EvidenceSourceType> SupportedSources => new[]
    {
        EvidenceSourceType.NetAccounts,
        EvidenceSourceType.Other
    };

    public bool CanParse(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.NetAccounts || source == EvidenceSourceType.Other;
    }

    public ParseResult<NetAccountsData> Parse(string input)
    {
        return ParseInternal(input);
    }

    public Task<ParseResult<NetAccountsData>> ParseAsync(string input)
    {
        return Task.FromResult(ParseInternal(input));
    }

    /// <summary>
    /// Extract a single setting value by canonical key.
    /// Returns Missing if the setting does not exist.
    /// </summary>
    public ParseResult<string> ExtractSetting(string rawOutput, string canonicalKey)
    {
        var parseResult = ParseInternal(rawOutput);

        if (!parseResult.IsSuccess || parseResult.Value == null)
        {
            return parseResult.Map(_ => string.Empty);
        }

        var data = parseResult.Value;

        if (!data.HasSetting(canonicalKey))
        {
            return ParseResult<string>.Missing(
                $"Setting '{canonicalKey}' not found in net accounts output",
                rawOutput);
        }

        return ParseResult<string>.Success(data.GetRaw(canonicalKey)!, rawOutput);
    }

    // === PRIVATE ===

    private ParseResult<NetAccountsData> ParseInternal(string rawOutput)
    {
        // Missing: empty/null input
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return ParseResult<NetAccountsData>.Missing(
                "net accounts output is empty - command may have failed",
                rawOutput);
        }

        try
        {
            var data = new NetAccountsData();
            var lines = NormalizeLines(rawOutput);
            var parsedCount = 0;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (string.IsNullOrEmpty(trimmed))
                    continue;

                // Skip completion footer
                if (trimmed.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Must contain "Key: Value" separator
                var colonIndex = trimmed.IndexOf(':');
                if (colonIndex <= 0)
                    continue;

                var rawKey = trimmed.Substring(0, colonIndex).Trim();
                var rawValue = trimmed.Substring(colonIndex + 1).Trim();

                var canonicalKey = NormalizeKey(rawKey);

                // Unknown keys are still preserved raw for audit
                data.RawSettings[canonicalKey] = rawValue;

                // Map canonical key to typed property
                ApplyTypedValue(data, canonicalKey, rawValue);
                parsedCount++;
            }

            // Invalid: no settings parsed at all
            if (parsedCount == 0)
            {
                return ParseResult<NetAccountsData>.Invalid(
                    "No 'Key: Value' settings found - not a valid net accounts output",
                    rawOutput);
            }

            return ParseResult<NetAccountsData>.Success(data, rawOutput);
        }
        catch (Exception ex)
        {
            return ParseResult<NetAccountsData>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Unexpected error parsing net accounts output: {ex.Message}",
                rawOutput);
        }
    }

    /// <summary>
    /// Normalize a raw key line into a canonical key for stable lookup.
    /// </summary>
    private static string NormalizeKey(string rawKey)
    {
        var key = rawKey.ToLowerInvariant().Trim();

        // Canonical mapping (English output; locale variants added in later phase)
        if (key.StartsWith("force user logoff")) return "ForceUserLogoff";
        if (key.StartsWith("minimum password age")) return "MinimumPasswordAge";
        if (key.StartsWith("maximum password age")) return "MaximumPasswordAge";
        if (key.StartsWith("minimum password length")) return "MinimumPasswordLength";
        if (key.StartsWith("length of password history")) return "PasswordHistoryLength";
        if (key.StartsWith("lockout threshold")) return "LockoutThreshold";
        if (key.StartsWith("lockout duration")) return "LockoutDuration";
        if (key.StartsWith("lockout observation window")) return "LockoutObservationWindow";
        if (key.StartsWith("computer role")) return "ComputerRole";

        // Unknown key: keep normalized raw form
        return rawKey.Trim();
    }

    private static void ApplyTypedValue(NetAccountsData data, string canonicalKey, string rawValue)
    {
        switch (canonicalKey)
        {
            case "ForceUserLogoff":
                data.ForceUserLogoffRaw = rawValue;
                if (IsNever(rawValue))
                {
                    data.ForceUserLogoffNever = true;
                }
                else if (int.TryParse(rawValue, out var logoff))
                {
                    data.ForceUserLogoffMinutes = logoff;
                }
                break;

            case "MinimumPasswordAge":
                if (int.TryParse(rawValue, out var minAge))
                    data.MinimumPasswordAgeDays = minAge;
                break;

            case "MaximumPasswordAge":
                if (IsNever(rawValue) || IsUnlimited(rawValue))
                {
                    data.MaximumPasswordAgeUnlimited = true;
                }
                else if (int.TryParse(rawValue, out var maxAge))
                {
                    data.MaximumPasswordAgeDays = maxAge;
                }
                break;

            case "MinimumPasswordLength":
                if (int.TryParse(rawValue, out var minLen))
                    data.MinimumPasswordLength = minLen;
                break;

            case "PasswordHistoryLength":
                if (int.TryParse(rawValue, out var histLen))
                    data.PasswordHistoryLength = histLen;
                break;

            case "LockoutThreshold":
                if (IsNever(rawValue))
                {
                    data.LockoutDisabled = true;
                    data.LockoutThreshold = 0;
                }
                else if (int.TryParse(rawValue, out var threshold))
                {
                    data.LockoutThreshold = threshold;
                }
                break;

            case "LockoutDuration":
                if (int.TryParse(rawValue, out var duration))
                    data.LockoutDurationMinutes = duration;
                break;

            case "LockoutObservationWindow":
                if (int.TryParse(rawValue, out var window))
                    data.LockoutObservationWindowMinutes = window;
                break;

            case "ComputerRole":
                data.ComputerRole = rawValue;
                break;
        }
    }

    private static bool IsNever(string value)
    {
        return value.Equals("Never", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnlimited(string value)
    {
        return value.Equals("Unlimited", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> NormalizeLines(string rawOutput)
    {
        var cleaned = rawOutput
            .Replace("\0", string.Empty)
            .TrimStart('\uFEFF', '\uFFFE');

        return cleaned.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
    }
}