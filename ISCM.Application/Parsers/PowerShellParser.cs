using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses raw PowerShell command output into structured PowerShellData.
/// 
/// Detects output type and extracts typed values:
///   - Boolean: True/False
///   - Integer/Long: numeric values
///   - String: plain text
///   - JSON: { "key": "value" } simple objects
///   - MultiLine: first non-empty line + all lines
///   - Array: @() or array literal
/// 
/// Backward compatibility: also implements legacy IEvidenceParser for existing checks.
/// </summary>
public class PowerShellParser : IParser<string, PowerShellData>, IEvidenceParser
{
    public string Name => "PowerShellParser";
    public string Version => "1.0.0";

    public IEnumerable<EvidenceSourceType> SupportedSources => new[]
    {
        EvidenceSourceType.PowerShell,
        EvidenceSourceType.Other
    };

    public bool CanParse(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.PowerShell || source == EvidenceSourceType.Other;
    }

    // === IParser<string, PowerShellData> ===

    public ParseResult<PowerShellData> Parse(string input)
    {
        return ParseInternal(input);
    }

    public Task<ParseResult<PowerShellData>> ParseAsync(string input)
    {
        return Task.FromResult(ParseInternal(input));
    }

    // === IEvidenceParser (legacy) ===

    string IEvidenceParser.Parse(string rawOutput, string sourceType)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return string.Empty;

        var result = ParseInternal(rawOutput);

        if (!result.IsSuccess)
        {
            return string.Empty;
        }

        return result.Value?.GetStringValue() ?? string.Empty;
    }

    // === PRIVATE ===

    private ParseResult<PowerShellData> ParseInternal(string rawOutput)
    {
        // Missing: empty/null input
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return ParseResult<PowerShellData>.Missing(
                "PowerShell output is empty - command may have failed or returned nothing",
                rawOutput);
        }

        try
        {
            var data = new PowerShellData { RawOutput = rawOutput };
            var trimmed = rawOutput.Trim();

            // Case 1: Boolean (True/False)
            if (bool.TryParse(trimmed, out var boolVal))
            {
                data.OutputType = PowerShellOutputType.Boolean;
                data.BooleanValue = boolVal;
                return ParseResult<PowerShellData>.Success(data, rawOutput);
            }

            // Case 2: Integer
            if (int.TryParse(trimmed, out var intVal))
            {
                data.OutputType = PowerShellOutputType.Integer;
                data.IntegerValue = intVal;
                return ParseResult<PowerShellData>.Success(data, rawOutput);
            }

            // Case 3: Long
            if (long.TryParse(trimmed, out var longVal))
            {
                data.OutputType = PowerShellOutputType.Long;
                data.LongValue = longVal;
                return ParseResult<PowerShellData>.Success(data, rawOutput);
            }

            // Case 4: JSON object (simple key-value)
            if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
            {
                var parseResult = ParseJsonOutput(trimmed);
                if (parseResult.IsSuccess)
                {
                    data.OutputType = PowerShellOutputType.Json;
                    foreach (var kvp in parseResult.Value!)
                    {
                        data.JsonProperties[kvp.Key] = kvp.Value;
                    }
                    return ParseResult<PowerShellData>.Success(data, rawOutput);
                }
                // JSON parse failed: fall through to MultiLine
            }

            // Case 5: Array literal @() or [item1, item2]
            if (trimmed.StartsWith("@(") && trimmed.EndsWith(")"))
            {
                var inner = trimmed.Substring(2, trimmed.Length - 3);
                var items = ParseArrayItems(inner);
                data.OutputType = PowerShellOutputType.Array;
                data.ArrayItems.AddRange(items);
                return ParseResult<PowerShellData>.Success(data, rawOutput);
            }

            // Case 6: Multi-line output
            var lines = trimmed
                .Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l))
                .ToList();

            if (lines.Count == 0)
            {
                return ParseResult<PowerShellData>.Missing(
                    "PowerShell output contained only whitespace",
                    rawOutput);
            }

            data.OutputType = lines.Count == 1 ? PowerShellOutputType.String : PowerShellOutputType.MultiLine;
            data.StringValue = lines[0];
            data.Lines.AddRange(lines);

            return ParseResult<PowerShellData>.Success(data, rawOutput);
        }
        catch (Exception ex)
        {
            return ParseResult<PowerShellData>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Unexpected error parsing PowerShell output: {ex.Message}",
                rawOutput);
        }
    }

    private static ParseResult<Dictionary<string, string>> ParseJsonOutput(string json)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Remove outer braces
            var inner = json.Trim();
            if (inner.StartsWith("{")) inner = inner.Substring(1);
            if (inner.EndsWith("}")) inner = inner.Substring(0, inner.Length - 1);
            inner = inner.Trim();

            if (string.IsNullOrEmpty(inner))
            {
                return ParseResult<Dictionary<string, string>>.Success(result, json);
            }

            // Split by comma, respecting quoted strings
            var pairs = SplitJsonPairs(inner);

            foreach (var pair in pairs)
            {
                var colonIndex = pair.IndexOf(':');
                if (colonIndex <= 0) continue;

                var key = pair.Substring(0, colonIndex).Trim().Trim('"');
                var value = pair.Substring(colonIndex + 1).Trim().Trim('"');

                if (!string.IsNullOrEmpty(key))
                {
                    result[key] = value;
                }
            }

            return ParseResult<Dictionary<string, string>>.Success(result, json);
        }
        catch (Exception ex)
        {
            return ParseResult<Dictionary<string, string>>.Failure(
                ParseErrorCode.InvalidFormat,
                $"Failed to parse JSON: {ex.Message}",
                json);
        }
    }

    private static List<string> SplitJsonPairs(string inner)
    {
        var pairs = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        var depth = 0;

        foreach (var c in inner)
        {
            if (c == '"' && depth == 0)
            {
                inQuotes = !inQuotes;
                current.Append(c);
            }
            else if (c == '{' || c == '[')
            {
                depth++;
                current.Append(c);
            }
            else if (c == '}' || c == ']')
            {
                depth--;
                current.Append(c);
            }
            else if (c == ',' && !inQuotes && depth == 0)
            {
                pairs.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            pairs.Add(current.ToString());
        }

        return pairs;
    }

    private static List<string> ParseArrayItems(string inner)
    {
        var items = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        var depth = 0;

        foreach (var c in inner)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                current.Append(c);
            }
            else if (c == '(' || c == '[' || c == '{')
            {
                depth++;
                current.Append(c);
            }
            else if (c == ')' || c == ']' || c == '}')
            {
                depth--;
                current.Append(c);
            }
            else if (c == ',' && !inQuotes && depth == 0)
            {
                var item = current.ToString().Trim().Trim('"');
                if (!string.IsNullOrEmpty(item))
                {
                    items.Add(item);
                }
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        var last = current.ToString().Trim().Trim('"');
        if (!string.IsNullOrEmpty(last))
        {
            items.Add(last);
        }

        return items;
    }
}