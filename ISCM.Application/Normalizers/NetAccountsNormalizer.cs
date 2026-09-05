using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Normalizers;

/// <summary>
/// Converts ParseResult<NetAccountsData> into ParseResult<EvidenceValue>.
/// 
/// Two modes:
///   1. Normalize(...)         → whole data as StructuredObject
///   2. NormalizeSetting(...)  → single setting as unit-aware typed EvidenceValue
/// 
/// Unit-aware mapping (BUG-02 safe - each setting individual):
///   MinimumPasswordAge        → Integer (unit: days)
///   MaximumPasswordAge        → Integer (unit: days) / "Unlimited"
///   MinimumPasswordLength     → Integer (no unit)
///   PasswordHistoryLength     → Integer (no unit)
///   LockoutThreshold          → Integer (no unit)
///   LockoutDuration           → Integer (unit: minutes)
///   LockoutObservationWindow  → Integer (unit: minutes)
///   ForceUserLogoff           → Integer (unit: minutes) / "Never"
///   ComputerRole              → String
/// 
/// Propagation rules:
///   - Missing/Invalid/Error parse states propagate explicitly
///   - Missing setting → Missing (never fabricated)
///   - No silent defaults
/// </summary>
public class NetAccountsNormalizer : IEvidenceNormalizer<NetAccountsData>
{
    public string Name => "NetAccountsNormalizer";

    public EvidenceSourceType SourceType => EvidenceSourceType.NetAccounts;

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.NetAccounts
            || source == EvidenceSourceType.Other;
    }

    /// <summary>
    /// Convert the entire parsed data into a StructuredObject EvidenceValue.
    /// </summary>
    public ParseResult<EvidenceValue> Normalize(ParseResult<NetAccountsData> parseResult)
    {
        if (parseResult == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is null");
        }

        var failed = PropagateFailedState(parseResult);
        if (failed != null) return failed;

        if (parseResult.Value == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is Success but Value is null",
                parseResult.RawInput);
        }

        return ParseResult<EvidenceValue>.Success(
            new EvidenceValue(
                value: parseResult.Value,
                type: EvidenceValueType.StructuredObject,
                unit: null,
                rawString: parseResult.Value.ToString()),
            parseResult.RawInput);
    }

    /// <summary>
    /// Extract and normalize a single setting into a unit-aware typed EvidenceValue.
    /// This is the primary method used by evaluation logic.
    /// </summary>
    public ParseResult<EvidenceValue> NormalizeSetting(
        ParseResult<NetAccountsData> parseResult,
        string canonicalKey)
    {
        if (parseResult == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is null");
        }

        var failed = PropagateFailedState(parseResult);
        if (failed != null) return failed;

        var data = parseResult.Value;
        if (data == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is Success but Value is null",
                parseResult.RawInput);
        }

        // Missing setting → Missing (explicit)
        if (!data.HasSetting(canonicalKey))
        {
            return ParseResult<EvidenceValue>.Missing(
                $"Setting '{canonicalKey}' not found in net accounts output",
                parseResult.RawInput);
        }

        try
        {
            var evidenceValue = ConvertSetting(data, canonicalKey);
            return ParseResult<EvidenceValue>.Success(evidenceValue, parseResult.RawInput);
        }
        catch (Exception ex)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Failed to convert setting '{canonicalKey}': {ex.Message}",
                parseResult.RawInput);
        }
    }

    /// <summary>
    /// Unit-aware, type-preserving conversion of a single setting.
    /// </summary>
    private static EvidenceValue ConvertSetting(NetAccountsData data, string canonicalKey)
    {
        switch (canonicalKey)
        {
            case "MinimumPasswordAge":
                return IntValue(data.MinimumPasswordAgeDays, "days", data, "MinimumPasswordAge");

            case "MaximumPasswordAge":
                // Unlimited is a semantic state, not a number
                if (data.MaximumPasswordAgeUnlimited)
                    return StringValue("Unlimited", data, "MaximumPasswordAge");
                return IntValue(data.MaximumPasswordAgeDays, "days", data, "MaximumPasswordAge");

            case "MinimumPasswordLength":
                return IntValue(data.MinimumPasswordLength, null, data, "MinimumPasswordLength");

            case "PasswordHistoryLength":
                return IntValue(data.PasswordHistoryLength, null, data, "PasswordHistoryLength");

            case "LockoutThreshold":
                return IntValue(data.LockoutThreshold, null, data, "LockoutThreshold");

            case "LockoutDuration":
                return IntValue(data.LockoutDurationMinutes, "minutes", data, "LockoutDuration");

            case "LockoutObservationWindow":
                return IntValue(data.LockoutObservationWindowMinutes, "minutes", data, "LockoutObservationWindow");

            case "ForceUserLogoff":
                // Never is a semantic state, not a number
                if (data.ForceUserLogoffNever)
                    return StringValue("Never", data, "ForceUserLogoff");
                return IntValue(data.ForceUserLogoffMinutes, "minutes", data, "ForceUserLogoff");

            case "ComputerRole":
                return StringValue(data.ComputerRole ?? string.Empty, data, "ComputerRole");

            default:
                // Unknown canonical key: fall back to raw string (no fabrication)
                var raw = data.GetRaw(canonicalKey);
                return StringValue(raw ?? string.Empty, data, canonicalKey);
        }
    }

    private static EvidenceValue IntValue(int? value, string? unit, NetAccountsData data, string key)
    {
        if (value == null)
        {
            // Typed value missing but raw exists: try raw parse (no silent default)
            var raw = data.GetRaw(key);
            if (raw != null && int.TryParse(raw, out var parsed))
            {
                return new EvidenceValue(parsed, EvidenceValueType.Integer, unit, raw);
            }
            throw new InvalidOperationException(
                $"Setting '{key}' has no numeric value (raw: {raw ?? "null"})");
        }

        return new EvidenceValue(value.Value, EvidenceValueType.Integer, unit, value.Value.ToString());
    }

    private static EvidenceValue StringValue(string value, NetAccountsData data, string key)
    {
        return new EvidenceValue(value, EvidenceValueType.String, null, value);
    }

    /// <summary>
    /// Returns a failed ParseResult if the input parse state is not Success, else null.
    /// </summary>
    private static ParseResult<EvidenceValue>? PropagateFailedState(
        ParseResult<NetAccountsData> parseResult)
    {
        if (parseResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                parseResult.Error?.Message ?? "net accounts output is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                parseResult.Error?.Message ?? "net accounts output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<EvidenceValue>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "net accounts parse failed",
                parseResult.RawInput);
        }

        return null;
    }
}