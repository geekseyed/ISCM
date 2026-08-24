using ISCM.Application.Interfaces;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses raw PowerShell command output into structured values.
/// Handles various PowerShell output formats.
/// </summary>
public class PowerShellParser : IEvidenceParser
{
    public string Parse(string rawOutput, string sourceType)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return string.Empty;

        var trimmed = rawOutput.Trim();

        // Case 1: Boolean output (True/False)
        if (bool.TryParse(trimmed, out bool boolVal))
        {
            return boolVal ? "True" : "False";
        }

        // Case 2: Numeric output
        if (int.TryParse(trimmed, out int intVal))
        {
            return intVal.ToString();
        }

        // Case 3: JSON output (simple key-value)
        if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
        {
            return ParseJsonOutput(trimmed);
        }

        // Case 4: Multi-line output (take first non-empty line)
        var lines = trimmed.Split('\n');
        foreach (var line in lines)
        {
            var lineTrimmed = line.Trim();
            if (!string.IsNullOrEmpty(lineTrimmed))
            {
                return lineTrimmed;
            }
        }

        return trimmed;
    }

    private string ParseJsonOutput(string json)
    {
        // Simple JSON parser for basic key-value pairs
        // Example: {"Enabled":true,"Value":123}
        try
        {
            // Remove braces
            var inner = json.Trim('{', '}').Trim();

            // Split by comma for multiple properties
            var pairs = inner.Split(',');
            var results = new System.Collections.Generic.List<string>();

            foreach (var pair in pairs)
            {
                var keyValue = pair.Split(':');
                if (keyValue.Length == 2)
                {
                    var key = keyValue[0].Trim().Trim('"');
                    var value = keyValue[1].Trim().Trim('"');
                    results.Add($"{key}={value}");
                }
            }

            return string.Join(", ", results);
        }
        catch
        {
            return json;
        }
    }
}