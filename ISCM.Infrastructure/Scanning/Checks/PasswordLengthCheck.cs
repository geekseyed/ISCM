using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.3: Password Policy Check (Collector-only pattern).
/// 
/// این چک **فقط Collector** است:
/// - Evidence تولید می‌کند (RawOutput + TypedValue)
/// - Evidence.Evaluation = NotScanned (ارزیابی نمی‌کند)
/// - Scanner مسئول ارزیابی تایپ‌شده با استفاده از کاتالوگ است
/// </summary>
[SupportedOSPlatform("windows")]
public class PasswordLengthCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    public override string CheckId => "PWD-001";
    public override string Name => "Password Policy";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.High;

    private const string PasswordPolicyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public PasswordLengthCheck()
    {
        _registryParser = new RegistryParser();
    }

    /// <summary>
    /// Phase 10.3: Collects evidence for all 6 password policy SubControls.
    /// </summary>
    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        evidenceList.Add(await CollectMinimumPasswordLength());
        evidenceList.Add(await CollectPasswordHistory());
        evidenceList.Add(await CollectMaximumPasswordAge());
        evidenceList.Add(await CollectMinimumPasswordAge());
        evidenceList.Add(await CollectPasswordComplexity());
        evidenceList.Add(await CollectReversibleEncryption());

        return evidenceList;
    }

    private async Task<Evidence> CollectMinimumPasswordLength()
    {
        var subControlId = "PWD-001.4";
        var startTime = DateTime.UtcNow;

        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(PasswordPolicyPath))
            {
                var value = key?.GetValue("MinimumPasswordLength");
                rawOutput = value?.ToString() ?? "Not configured";
            }

            if (rawOutput == "Not configured")
            {
                rawOutput = await RunCommandAsync("net", "accounts");
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractIntegerFromOutput(rawOutput, "Minimum password length");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "MinimumPasswordLength",
                AcquisitionCommand = $"reg query HKLM\\{PasswordPolicyPath} /v MinimumPasswordLength",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "MinimumPasswordLength",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<Evidence> CollectPasswordHistory()
    {
        var subControlId = "PWD-001.1";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractIntegerFromOutput(rawOutput, "Length of password history maintained");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                AcquisitionCommand = "net accounts",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<Evidence> CollectMaximumPasswordAge()
    {
        var subControlId = "PWD-001.2";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractDurationFromOutput(rawOutput, "Maximum password age", "days");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                AcquisitionCommand = "net accounts",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<Evidence> CollectMinimumPasswordAge()
    {
        var subControlId = "PWD-001.3";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractDurationFromOutput(rawOutput, "Minimum password age", "days");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                AcquisitionCommand = "net accounts",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<Evidence> CollectPasswordComplexity()
    {
        var subControlId = "PWD-001.5";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractBooleanFromOutput(rawOutput, "complexity");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                AcquisitionCommand = "net accounts",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<Evidence> CollectReversibleEncryption()
    {
        var subControlId = "PWD-001.6";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractBooleanFromOutput(rawOutput, "reversible");

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                AcquisitionCommand = "net accounts",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.NetAccounts,
                SourceName = "net accounts",
                RawOutput = ex.Message,
                TypedValue = null,
                Evaluation = CheckStatus.Error,
                Error = ex.Message,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    // Helper methods to extract typed values from raw output

    private static EvidenceValue ExtractIntegerFromOutput(string rawOutput, string keyword)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        // Try to extract value from specific line containing keyword
        var lines = rawOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                // Check for "None" keyword
                if (line.Contains("None", StringComparison.OrdinalIgnoreCase))
                    return EvidenceValue.FromInteger(0);

                // Try to extract number from this line
                var match = Regex.Match(line, @"(\d+)");
                if (match.Success && int.TryParse(match.Groups[1].Value, out var value))
                    return EvidenceValue.FromInteger(value);
            }
        }

        // Fallback: try to extract first number from entire output
        var match2 = Regex.Match(rawOutput, @"(\d+)");
        if (match2.Success && int.TryParse(match2.Groups[1].Value, out var fallbackValue))
            return EvidenceValue.FromInteger(fallbackValue);

        return EvidenceValue.FromInteger(0);
    }

    private static EvidenceValue ExtractDurationFromOutput(string rawOutput, string keyword, string unit)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Days));

        // Try to extract value from specific line containing keyword
        var lines = rawOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                // Check for "Unlimited" in THIS line only (not entire output)
                if (line.Contains("Unlimited", StringComparison.OrdinalIgnoreCase))
                {
                    // Unlimited = 99999 days (effectively infinite, will fail any reasonable threshold)
                    return EvidenceValue.FromDuration(new DurationValue(99999, DurationUnit.Days));
                }

                // Try to extract duration from this line
                var match = Regex.Match(line, @"(\d+)\s*(days?|hours?|minutes?|seconds?)", RegexOptions.IgnoreCase);
                if (match.Success && int.TryParse(match.Groups[1].Value, out var durationValue))
                {
                    var durationUnit = match.Groups[2].Value.ToLower() switch
                    {
                        "day" or "days" => DurationUnit.Days,
                        "hour" or "hours" => DurationUnit.Hours,
                        "minute" or "minutes" => DurationUnit.Minutes,
                        "second" or "seconds" => DurationUnit.Seconds,
                        _ => DurationUnit.Days
                    };
                    return EvidenceValue.FromDuration(new DurationValue(durationValue, durationUnit));
                }

                // Fallback: extract any number from this line
                var numMatch = Regex.Match(line, @"(\d+)");
                if (numMatch.Success && int.TryParse(numMatch.Groups[1].Value, out var numValue))
                    return EvidenceValue.FromDuration(new DurationValue(numValue, DurationUnit.Days));
            }
        }

        // Fallback: return 0 if keyword not found
        return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Days));
    }

    private static EvidenceValue ExtractBooleanFromOutput(string rawOutput, string keyword)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        // Try to extract boolean from text
        if (rawOutput.Contains("Enabled", StringComparison.OrdinalIgnoreCase) ||
            rawOutput.Contains("Yes", StringComparison.OrdinalIgnoreCase) ||
            rawOutput.Contains("True", StringComparison.OrdinalIgnoreCase))
            return EvidenceValue.FromBoolean(true);

        if (rawOutput.Contains("Disabled", StringComparison.OrdinalIgnoreCase) ||
            rawOutput.Contains("No", StringComparison.OrdinalIgnoreCase) ||
            rawOutput.Contains("False", StringComparison.OrdinalIgnoreCase))
            return EvidenceValue.FromBoolean(false);

        return EvidenceValue.FromBoolean(false);
    }

    private static async Task<string> RunCommandAsync(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return "Process not started";

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }
}