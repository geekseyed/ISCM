using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses raw Registry output into structured RegistryValueData.
/// Handles direct Registry API results and reg.exe / PowerShell command output.
/// 
/// MUST NOT silently convert malformed input into a valid default.
/// MUST explicitly distinguish:
///   - Success: value parsed with correct type
///   - Missing: key/value not found
///   - Invalid: malformed output
///   - Error: access denied, unexpected format
/// 
/// Backward compatibility: also implements legacy IEvidenceParser for existing checks.
/// The legacy interface is kept during migration and will be removed in a future phase.
/// </summary>
public class RegistryParser : IParser<string, RegistryValueData>, IEvidenceParser
{
    // === IParser<string, RegistryValueData> ===

    public string Name => "RegistryParser";
    public string Version => "1.0.0";

    public IEnumerable<EvidenceSourceType> SupportedSources => new[]
    {
        EvidenceSourceType.Registry,
        EvidenceSourceType.PowerShell,
        EvidenceSourceType.Other
    };

    public bool CanParse(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Registry
            || source == EvidenceSourceType.PowerShell
            || source == EvidenceSourceType.Other;
    }

    public ParseResult<RegistryValueData> Parse(string input)
    {
        return ParseInternal(input, EvidenceSourceType.Registry, string.Empty, string.Empty);
    }

    public Task<ParseResult<RegistryValueData>> ParseAsync(string input)
    {
        return Task.FromResult(Parse(input));
    }

    /// <summary>
    /// Parse with explicit source type, key path, and value name context.
    /// This is the recommended method for production use.
    /// </summary>
    public ParseResult<RegistryValueData> ParseWithContext(
        string rawOutput,
        string sourceType,
        string keyPath,
        string valueName)
    {
        if (string.IsNullOrWhiteSpace(sourceType))
        {
            return ParseResult<RegistryValueData>.Invalid(
                "sourceType is required",
                rawOutput);
        }

        var source = sourceType.ToLowerInvariant() switch
        {
            "registryreader" or "registry" or "registry_api" => EvidenceSourceType.Registry,
            "reg.exe" => EvidenceSourceType.Other,
            "powershell" => EvidenceSourceType.PowerShell,
            _ => EvidenceSourceType.Other
        };

        return ParseInternal(rawOutput, source, keyPath, valueName);
    }

    // === IEvidenceParser (legacy) ===

    /// <summary>
    /// Legacy Parse method for backward compatibility with existing checks.
    /// Delegates to the new typed parser and returns only the string representation.
    /// </summary>
    string IEvidenceParser.Parse(string rawOutput, string sourceType)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return string.Empty;

        var result = ParseWithContext(
            rawOutput,
            sourceType ?? string.Empty,
            keyPath: string.Empty,
            valueName: string.Empty);

        if (!result.IsSuccess)
        {
            // Legacy contract returned empty string on failure
            return string.Empty;
        }

        // Extract string representation from typed result
        var data = result.Value?.Data;
        return data switch
        {
            null => string.Empty,
            string s => s,
            int i => i.ToString(),
            long l => l.ToString(),
            string[] arr => string.Join(",", arr),
            _ => data.ToString() ?? string.Empty
        };
    }

    // === PRIVATE METHODS ===

    private ParseResult<RegistryValueData> ParseInternal(
        string rawOutput,
        EvidenceSourceType source,
        string keyPath,
        string valueName)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return ParseResult<RegistryValueData>.Missing(
                "Registry value is empty or null - key or value may not exist",
                rawOutput);
        }

        try
        {
            return source switch
            {
                EvidenceSourceType.Registry => ParseRegistryApiOutput(rawOutput, keyPath, valueName),
                EvidenceSourceType.PowerShell => ParsePowerShellOutput(rawOutput, keyPath, valueName),
                EvidenceSourceType.Other => ParseRegExeOutput(rawOutput, keyPath, valueName),
                _ => ParseResult<RegistryValueData>.Invalid(
                    $"Unsupported source type: {source}",
                    rawOutput)
            };
        }
        catch (UnauthorizedAccessException)
        {
            return ParseResult<RegistryValueData>.Failure(
                ParseErrorCode.AccessDenied,
                "Access denied to registry key/value",
                rawOutput);
        }
        catch (Exception ex)
        {
            return ParseResult<RegistryValueData>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Unexpected error parsing registry output: {ex.Message}",
                rawOutput);
        }
    }

    private ParseResult<RegistryValueData> ParseRegistryApiOutput(
        string rawOutput,
        string keyPath,
        string valueName)
    {
        var trimmed = rawOutput.Trim();

        if (int.TryParse(trimmed, out var intValue))
        {
            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.DWord, intValue),
                rawOutput);
        }

        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(
                trimmed.Substring(2),
                System.Globalization.NumberStyles.HexNumber,
                null,
                out var hexValue))
        {
            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.DWord, hexValue),
                rawOutput);
        }

        if (long.TryParse(trimmed, out var longValue))
        {
            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.QWord, longValue),
                rawOutput);
        }

        return ParseResult<RegistryValueData>.Success(
            new RegistryValueData(keyPath, valueName, RegistryDataType.String, trimmed),
            rawOutput);
    }

    private ParseResult<RegistryValueData> ParseRegExeOutput(
        string rawOutput,
        string keyPath,
        string valueName)
    {
        var lines = rawOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed))
                continue;

            if (trimmed.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
                continue;

            var parsedValueName = parts[0];
            var regTypeStr = parts[1].ToUpperInvariant();
            var rawValue = string.Join(" ", parts.Skip(2));

            if (!regTypeStr.StartsWith("REG_"))
                continue;

            if (!TryGetRegistryDataType(regTypeStr, out var dataType))
            {
                return ParseResult<RegistryValueData>.Invalid(
                    $"Unknown registry type: {regTypeStr}",
                    rawOutput);
            }

            var effectiveValueName = !string.IsNullOrEmpty(valueName) ? valueName : parsedValueName;
            return ParseTypedValue(dataType, rawValue, keyPath, effectiveValueName, rawOutput);
        }

        return ParseResult<RegistryValueData>.Missing(
            "No registry value line found in reg.exe output",
            rawOutput);
    }

    private ParseResult<RegistryValueData> ParsePowerShellOutput(
        string rawOutput,
        string keyPath,
        string valueName)
    {
        var trimmed = rawOutput.Trim();

        if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
        {
            var inner = trimmed.Substring(1, trimmed.Length - 2);
            var items = inner.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                             .Select(s => s.Trim())
                             .ToArray();

            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.MultiString, items),
                rawOutput);
        }

        if (int.TryParse(trimmed, out var intValue))
        {
            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.DWord, intValue),
                rawOutput);
        }

        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(
                trimmed.Substring(2),
                System.Globalization.NumberStyles.HexNumber,
                null,
                out var hexValue))
        {
            return ParseResult<RegistryValueData>.Success(
                new RegistryValueData(keyPath, valueName, RegistryDataType.DWord, hexValue),
                rawOutput);
        }

        return ParseResult<RegistryValueData>.Success(
            new RegistryValueData(keyPath, valueName, RegistryDataType.String, trimmed),
            rawOutput);
    }

    private ParseResult<RegistryValueData> ParseTypedValue(
        RegistryDataType dataType,
        string rawValue,
        string keyPath,
        string valueName,
        string fullRawOutput)
    {
        switch (dataType)
        {
            case RegistryDataType.DWord:
                if (TryParseDword(rawValue, out var dword))
                {
                    return ParseResult<RegistryValueData>.Success(
                        new RegistryValueData(keyPath, valueName, dataType, dword),
                        fullRawOutput);
                }
                return ParseResult<RegistryValueData>.Invalid(
                    $"Cannot parse '{rawValue}' as DWORD for value '{valueName}'",
                    fullRawOutput);

            case RegistryDataType.QWord:
                if (TryParseQword(rawValue, out var qword))
                {
                    return ParseResult<RegistryValueData>.Success(
                        new RegistryValueData(keyPath, valueName, dataType, qword),
                        fullRawOutput);
                }
                return ParseResult<RegistryValueData>.Invalid(
                    $"Cannot parse '{rawValue}' as QWORD for value '{valueName}'",
                    fullRawOutput);

            case RegistryDataType.MultiString:
                var items = rawValue.Split(new[] { '\0', ',', ';' }, StringSplitOptions.None)
                                    .Select(s => s.Trim())
                                    .ToArray();
                return ParseResult<RegistryValueData>.Success(
                    new RegistryValueData(keyPath, valueName, dataType, items),
                    fullRawOutput);

            case RegistryDataType.String:
            case RegistryDataType.ExpandString:
                return ParseResult<RegistryValueData>.Success(
                    new RegistryValueData(keyPath, valueName, dataType, rawValue),
                    fullRawOutput);

            case RegistryDataType.Binary:
                return ParseResult<RegistryValueData>.Success(
                    new RegistryValueData(keyPath, valueName, dataType, rawValue),
                    fullRawOutput);

            case RegistryDataType.Unknown:
            default:
                return ParseResult<RegistryValueData>.Invalid(
                    $"Unsupported registry type: {dataType} for value '{valueName}'",
                    fullRawOutput);
        }
    }

    private static bool TryParseDword(string value, out int result)
    {
        result = 0;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(
                value.Substring(2),
                System.Globalization.NumberStyles.HexNumber,
                null,
                out result);
        }
        return int.TryParse(value, out result);
    }

    private static bool TryParseQword(string value, out long result)
    {
        result = 0;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return long.TryParse(
                value.Substring(2),
                System.Globalization.NumberStyles.HexNumber,
                null,
                out result);
        }
        return long.TryParse(value, out result);
    }

    private static bool TryGetRegistryDataType(string regTypeStr, out RegistryDataType dataType)
    {
        switch (regTypeStr)
        {
            case "REG_SZ":
                dataType = RegistryDataType.String;
                return true;
            case "REG_EXPAND_SZ":
                dataType = RegistryDataType.ExpandString;
                return true;
            case "REG_MULTI_SZ":
                dataType = RegistryDataType.MultiString;
                return true;
            case "REG_DWORD":
                dataType = RegistryDataType.DWord;
                return true;
            case "REG_QWORD":
                dataType = RegistryDataType.QWord;
                return true;
            case "REG_BINARY":
                dataType = RegistryDataType.Binary;
                return true;
            case "REG_NONE":
                dataType = RegistryDataType.Unknown;
                return true;
            default:
                dataType = RegistryDataType.Unknown;
                return false;
        }
    }
}