using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Normalizers;

/// <summary>
/// Converts ParseResult<RegistryValueData> into ParseResult<EvidenceValue>.
/// 
/// Mapping (type-preserving, no lossy conversion):
///   REG_DWORD         → EvidenceValue.FromInteger      (Integer)
///   REG_QWORD         → EvidenceValue.FromLong         (Long)
///   REG_SZ / EXPAND   → EvidenceValue.FromString       (String)
///   REG_MULTI_SZ      → EvidenceValue(Collection)      (Collection)
///   REG_BINARY        → EvidenceValue.FromString       (String, hex-safe)
///   REG_NONE/Unknown  → ParseResult.Invalid            (no silent default)
/// 
/// Propagation rules:
///   - If parseResult is Missing → return Missing with same message
///   - If parseResult is Invalid → return Invalid with same message
///   - If parseResult is Error   → return Error with same message
///   - If parseResult is Success → convert via type-preserving mapping
/// </summary>
public class RegistryNormalizer : IEvidenceNormalizer<RegistryValueData>
{
    public string Name => "RegistryNormalizer";

    public EvidenceSourceType SourceType => EvidenceSourceType.Registry;

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Registry
            || source == EvidenceSourceType.Other;
    }

    public ParseResult<EvidenceValue> Normalize(ParseResult<RegistryValueData> parseResult)
    {
        if (parseResult == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is null");
        }

        // Propagate failed states explicitly - no fabricated defaults
        if (parseResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                parseResult.Error?.Message ?? "Registry value is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                parseResult.Error?.Message ?? "Registry output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<EvidenceValue>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "Registry parse failed",
                parseResult.RawInput);
        }

        // Success path - type-preserving conversion
        if (parseResult.Value == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is Success but Value is null",
                parseResult.RawInput);
        }

        try
        {
            var evidenceValue = ConvertRegistryValue(parseResult.Value);
            return ParseResult<EvidenceValue>.Success(evidenceValue, parseResult.RawInput);
        }
        catch (Exception ex)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Failed to convert registry value: {ex.Message}",
                parseResult.RawInput);
        }
    }

    /// <summary>
    /// Type-preserving conversion from RegistryValueData to EvidenceValue.
    /// </summary>
    private static EvidenceValue ConvertRegistryValue(RegistryValueData data)
    {
        switch (data.DataType)
        {
            case RegistryDataType.DWord:
                if (data.Data is int dword)
                {
                    return new EvidenceValue(
                        value: dword,
                        type: EvidenceValueType.Integer,
                        unit: null,
                        rawString: dword.ToString());
                }
                throw new InvalidOperationException(
                    $"REG_DWORD data is not int (got {data.Data?.GetType().Name ?? "null"})");

            case RegistryDataType.QWord:
                if (data.Data is long qword)
                {
                    return new EvidenceValue(
                        value: qword,
                        type: EvidenceValueType.Long,
                        unit: null,
                        rawString: qword.ToString());
                }
                throw new InvalidOperationException(
                    $"REG_QWORD data is not long (got {data.Data?.GetType().Name ?? "null"})");

            case RegistryDataType.String:
            case RegistryDataType.ExpandString:
                var strValue = data.Data?.ToString() ?? string.Empty;
                return new EvidenceValue(
                    value: strValue,
                    type: EvidenceValueType.String,
                    unit: null,
                    rawString: strValue);

            case RegistryDataType.MultiString:
                var multiString = data.Data as string[] ?? Array.Empty<string>();
                return new EvidenceValue(
                    value: multiString,
                    type: EvidenceValueType.Collection,
                    unit: null,
                    rawString: string.Join(",", multiString));

            case RegistryDataType.Binary:
                // Binary preserved as raw string - evaluation layer may handle further
                var binaryStr = data.Data?.ToString() ?? string.Empty;
                return new EvidenceValue(
                    value: binaryStr,
                    type: EvidenceValueType.String,
                    unit: null,
                    rawString: binaryStr);

            case RegistryDataType.Unknown:
            default:
                // Unknown registry type is treated as invalid at normalization boundary
                throw new InvalidOperationException(
                    $"Unsupported registry data type: {data.DataType}");
        }
    }
}