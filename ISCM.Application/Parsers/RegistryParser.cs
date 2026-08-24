using ISCM.Application.Interfaces;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses raw Registry output into structured values.
/// Handles both direct Registry API results and reg.exe command output.
/// </summary>
public class RegistryParser : IEvidenceParser
{
    public string Parse(string rawOutput, string sourceType)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return string.Empty;

        // Case 1: Direct Registry API (already parsed value)
        // If sourceType is "RegistryReader", rawOutput is already the value
        if (sourceType.Equals("RegistryReader", StringComparison.OrdinalIgnoreCase))
        {
            return rawOutput.Trim();
        }

        // Case 2: reg.exe command output
        // Format: "    ValueName    REG_TYPE    Value"
        if (sourceType.Equals("reg.exe", StringComparison.OrdinalIgnoreCase))
        {
            return ParseRegExeOutput(rawOutput);
        }

        // Case 3: PowerShell Get-ItemProperty output
        // Format: "ValueName : Value" or just "Value"
        if (sourceType.Equals("PowerShell", StringComparison.OrdinalIgnoreCase))
        {
            return ParsePowerShellOutput(rawOutput);
        }

        // Default: return trimmed raw output
        return rawOutput.Trim();
    }

    private string ParseRegExeOutput(string rawOutput)
    {
        // Example: "    DisableRealtimeMonitoring    REG_DWORD    0x0"
        var lines = rawOutput.Split('\n');
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed))
                continue;

            // Split by whitespace (REG_TYPE is in the middle)
            var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
            {
                // Last part is the value
                var value = parts[parts.Length - 1];

                // Convert hex to decimal if needed
                if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(value.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out int decVal))
                    {
                        return decVal.ToString();
                    }
                }

                return value;
            }
        }

        return string.Empty;
    }

    private string ParsePowerShellOutput(string rawOutput)
    {
        // Example: "1" or "True" or "Enabled"
        // PowerShell usually returns clean values
        return rawOutput.Trim();
    }
}