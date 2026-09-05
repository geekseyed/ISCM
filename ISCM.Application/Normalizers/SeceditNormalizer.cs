using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Normalizers;

/// <summary>
/// Converts ParseResult<SeceditPolicyData> into ParseResult<EvidenceValue>.
/// 
/// Two modes:
///   1. Normalize(...)       → whole policy as StructuredObject
///   2. NormalizeValue(...)  → single section/key value as typed EvidenceValue
/// 
/// Single-value mapping (type-preserving):
///   numeric string  → EvidenceValue.FromInteger  (Integer)
///   non-numeric     → EvidenceValue.FromString   (String)
/// 
/// Propagation rules:
///   - Missing/Invalid/Error parse states propagate explicitly
///   - Missing section/key → Missing (never fabricated)
///   - No silent defaults
/// </summary>
public class SeceditNormalizer : IEvidenceNormalizer<SeceditPolicyData>
{
    public string Name => "SeceditNormalizer";

    public EvidenceSourceType SourceType => EvidenceSourceType.Secedit;

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Secedit
            || source == EvidenceSourceType.Other;
    }

    /// <summary>
    /// Convert the entire parsed policy into a StructuredObject EvidenceValue.
    /// </summary>
    public ParseResult<EvidenceValue> Normalize(ParseResult<SeceditPolicyData> parseResult)
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
    /// Extract and normalize a single section/key value into a typed EvidenceValue.
    /// This is the primary method used by evaluation logic.
    /// </summary>
    public ParseResult<EvidenceValue> NormalizeValue(
        ParseResult<SeceditPolicyData> parseResult,
        string section,
        string key,
        string? unit = null)
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

        // Missing section → Missing
        if (!data.HasSection(section))
        {
            return ParseResult<EvidenceValue>.Missing(
                $"Section [{section}] not found in secedit output",
                parseResult.RawInput);
        }

        // Missing key → Missing
        if (!data.HasValue(section, key))
        {
            return ParseResult<EvidenceValue>.Missing(
                $"Key '{key}' not found in section [{section}]",
                parseResult.RawInput);
        }

        var rawValue = data.GetValue(section, key)!;

        try
        {
            var evidenceValue = ConvertSeceditValue(rawValue, unit);
            return ParseResult<EvidenceValue>.Success(evidenceValue, parseResult.RawInput);
        }
        catch (Exception ex)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Failed to convert secedit value '{key}': {ex.Message}",
                parseResult.RawInput);
        }
    }

    /// <summary>
    /// Type-preserving conversion of a single secedit value string.
    /// </summary>
    private static EvidenceValue ConvertSeceditValue(string rawValue, string? unit)
    {
        // Numeric → Integer
        if (int.TryParse(rawValue, out var intValue))
        {
            return new EvidenceValue(
                value: intValue,
                type: EvidenceValueType.Integer,
                unit: unit,
                rawString: rawValue);
        }

        // Large numeric → Long
        if (long.TryParse(rawValue, out var longValue))
        {
            return new EvidenceValue(
                value: longValue,
                type: EvidenceValueType.Long,
                unit: unit,
                rawString: rawValue);
        }

        // Non-numeric → String (e.g., paths, names)
        return new EvidenceValue(
            value: rawValue,
            type: EvidenceValueType.String,
            unit: unit,
            rawString: rawValue);
    }

    /// <summary>
    /// Returns a failed ParseResult if the input parse state is not Success, else null.
    /// </summary>
    private static ParseResult<EvidenceValue>? PropagateFailedState(
        ParseResult<SeceditPolicyData> parseResult)
    {
        if (parseResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                parseResult.Error?.Message ?? "Secedit output is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                parseResult.Error?.Message ?? "Secedit output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<EvidenceValue>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "Secedit parse failed",
                parseResult.RawInput);
        }

        return null;
    }
}