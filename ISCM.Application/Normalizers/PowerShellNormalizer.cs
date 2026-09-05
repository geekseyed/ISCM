using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Normalizers;

/// <summary>
/// Converts ParseResult<PowerShellData> into ParseResult<EvidenceValue>.
/// 
/// OutputType-driven mapping (type-preserving):
///   Boolean   → EvidenceValue.FromBoolean   (Boolean)
///   Integer   → EvidenceValue.FromInteger   (Integer)
///   Long      → EvidenceValue.FromLong      (Long)
///   String    → EvidenceValue.FromString    (String)
///   Json      → EvidenceValue(StructuredObject, JsonProperties)
///   MultiLine → EvidenceValue(Collection, Lines)
///   Array     → EvidenceValue(Collection, ArrayItems)
///   Unknown   → Invalid (explicit fail, no silent default)
/// 
/// Propagation rules:
///   - Missing/Invalid/Error parse states propagate explicitly
///   - No fabricated defaults
/// </summary>
public class PowerShellNormalizer : IEvidenceNormalizer<PowerShellData>
{
    public string Name => "PowerShellNormalizer";

    public EvidenceSourceType SourceType => EvidenceSourceType.PowerShell;

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.PowerShell
            || source == EvidenceSourceType.Other;
    }

    /// <summary>
    /// Convert the parsed PowerShell output into a typed EvidenceValue
    /// based on its detected OutputType.
    /// </summary>
    public ParseResult<EvidenceValue> Normalize(ParseResult<PowerShellData> parseResult)
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

        try
        {
            var evidenceValue = ConvertPowerShellData(data);
            return ParseResult<EvidenceValue>.Success(evidenceValue, parseResult.RawInput);
        }
        catch (Exception ex)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Failed to convert PowerShell output: {ex.Message}",
                parseResult.RawInput);
        }
    }

    /// <summary>
    /// Extract a single JSON property as a typed EvidenceValue.
    /// Returns Invalid if output is not JSON, Missing if property absent.
    /// </summary>
    public ParseResult<EvidenceValue> NormalizeJsonProperty(
        ParseResult<PowerShellData> parseResult,
        string key)
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

        // Not JSON → Invalid (explicit)
        if (!data.IsJson)
        {
            return ParseResult<EvidenceValue>.Invalid(
                $"PowerShell output is not JSON (got {data.OutputType})",
                parseResult.RawInput);
        }

        // Missing property → Missing (explicit)
        if (!data.HasJsonProperty(key))
        {
            return ParseResult<EvidenceValue>.Missing(
                $"JSON property '{key}' not found in PowerShell output",
                parseResult.RawInput);
        }

        var rawValue = data.GetJsonProperty(key)!;
        return ParseResult<EvidenceValue>.Success(
            ConvertScalarString(rawValue),
            parseResult.RawInput);
    }

    /// <summary>
    /// OutputType-driven, type-preserving conversion.
    /// </summary>
    private static EvidenceValue ConvertPowerShellData(PowerShellData data)
    {
        switch (data.OutputType)
        {
            case PowerShellOutputType.Boolean:
                if (data.BooleanValue == null)
                    throw new InvalidOperationException("Boolean output has no BooleanValue");
                return EvidenceValue.FromBoolean(data.BooleanValue.Value);

            case PowerShellOutputType.Integer:
                if (data.IntegerValue == null)
                    throw new InvalidOperationException("Integer output has no IntegerValue");
                return EvidenceValue.FromInteger(data.IntegerValue.Value);

            case PowerShellOutputType.Long:
                if (data.LongValue == null)
                    throw new InvalidOperationException("Long output has no LongValue");
                return EvidenceValue.FromLong(data.LongValue.Value);

            case PowerShellOutputType.String:
                return EvidenceValue.FromString(data.StringValue ?? string.Empty);

            case PowerShellOutputType.Json:
                return new EvidenceValue(
                    value: data.JsonProperties,
                    type: EvidenceValueType.StructuredObject,
                    unit: null,
                    rawString: data.RawOutput);

            case PowerShellOutputType.MultiLine:
                return new EvidenceValue(
                    value: data.Lines,
                    type: EvidenceValueType.Collection,
                    unit: null,
                    rawString: string.Join(Environment.NewLine, data.Lines));

            case PowerShellOutputType.Array:
                return new EvidenceValue(
                    value: data.ArrayItems,
                    type: EvidenceValueType.Collection,
                    unit: null,
                    rawString: string.Join(", ", data.ArrayItems));

            case PowerShellOutputType.Unknown:
            default:
                // Unknown output type is treated as invalid at normalization boundary
                throw new InvalidOperationException(
                    $"Unsupported PowerShell output type: {data.OutputType}");
        }
    }

    /// <summary>
    /// Convert a scalar string into the best typed EvidenceValue.
    /// </summary>
    private static EvidenceValue ConvertScalarString(string rawValue)
    {
        if (bool.TryParse(rawValue, out var boolVal))
            return EvidenceValue.FromBoolean(boolVal);

        if (int.TryParse(rawValue, out var intVal))
            return EvidenceValue.FromInteger(intVal);

        if (long.TryParse(rawValue, out var longVal))
            return EvidenceValue.FromLong(longVal);

        return EvidenceValue.FromString(rawValue);
    }

    /// <summary>
    /// Returns a failed ParseResult if the input parse state is not Success, else null.
    /// </summary>
    private static ParseResult<EvidenceValue>? PropagateFailedState(
        ParseResult<PowerShellData> parseResult)
    {
        if (parseResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                parseResult.Error?.Message ?? "PowerShell output is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                parseResult.Error?.Message ?? "PowerShell output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<EvidenceValue>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "PowerShell parse failed",
                parseResult.RawInput);
        }

        return null;
    }
}