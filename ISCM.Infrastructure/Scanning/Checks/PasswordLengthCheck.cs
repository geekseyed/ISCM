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
        // NO _evaluator field - Check should not evaluate!
    }

    /// <summary>
    /// Phase 10.3: Collects evidence for all 6 password policy SubControls.
    /// 
    /// Contract:
    /// - Returns 6 Evidence items (one per SubControl)
    /// - Each Evidence has RawOutput and TypedValue populated
    /// - Evidence.Evaluation = NotScanned (Scanner will evaluate)
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

            // Phase 10.3: Create Evidence with TypedValue
            var typedValue = ExtractIntegerFromOutput(rawOutput);

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
                Evaluation = CheckStatus.NotScanned, // Check does NOT evaluate
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
            var typedValue = ExtractIntegerFromOutput(rawOutput);

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
            var typedValue = ExtractDurationFromOutput(rawOutput, "days");

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
            var typedValue = ExtractDurationFromOutput(rawOutput, "days");

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
    private static EvidenceValue ExtractIntegerFromOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        // Try to parse as direct integer
        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        // Try to extract number from text like "14 characters" or "24 passwords remembered"
        var match = System.Text.RegularExpressions.Regex.Match(rawOutput, @"(\d+)");
        if (match.Success && int.TryParse(match.Groups[1].Value, out var extractedInt))
            return EvidenceValue.FromInteger(extractedInt);

        // Fallback: return as string if extraction fails
        return EvidenceValue.FromString(rawOutput);
    }

    private static EvidenceValue ExtractDurationFromOutput(string rawOutput, string unit)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Days));

        // Try to extract duration from text like "60 days", "15 minutes"
        var match = System.Text.RegularExpressions.Regex.Match(rawOutput, @"(\d+)\s*(days?|hours?|minutes?|seconds?)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
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

        // Fallback: try to extract any number and assume days
        var numMatch = System.Text.RegularExpressions.Regex.Match(rawOutput, @"(\d+)");
        if (numMatch.Success && int.TryParse(numMatch.Groups[1].Value, out var numValue))
            return EvidenceValue.FromDuration(new DurationValue(numValue, DurationUnit.Days));

        // Fallback: return as string if extraction fails
        return EvidenceValue.FromString(rawOutput);
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

        // Fallback: return as string if extraction fails
        return EvidenceValue.FromString(rawOutput);
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