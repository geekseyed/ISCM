using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.6: Account Lockout Policy Check (Collector-only pattern).
/// 
/// این چک **فقط Collector** است:
/// - Evidence تولید می‌کند (RawOutput + TypedValue)
/// - Evidence.Evaluation = NotScanned (ارزیابی نمی‌کند)
/// - Scanner مسئول ارزیابی تایپ‌شده با استفاده از کاتالوگ است
/// 
/// SubControls:
///   - LCK-001.1: Account lockout threshold (Integer, LessOrEqual, 5)
///   - LCK-001.2: Account lockout duration (Duration minutes, GreaterOrEqual, 15)
///   - LCK-001.3: Reset account lockout counter after (Duration minutes, GreaterOrEqual, 15)
/// </summary>
[SupportedOSPlatform("windows")]
public class AccountLockoutCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    public override string CheckId => "LCK-001";
    public override string Name => "Account Lockout Policy";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.High;

    public AccountLockoutCheck()
    {
        _registryParser = new RegistryParser();
    }

    /// <summary>
    /// Phase 10.6: Collects evidence for all 3 lockout policy SubControls.
    /// </summary>
    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        evidenceList.Add(await CollectLockoutThreshold());
        evidenceList.Add(await CollectLockoutDuration());
        evidenceList.Add(await CollectLockoutObservationWindow());

        return evidenceList;
    }

    private async Task<Evidence> CollectLockoutThreshold()
    {
        var subControlId = "LCK-001.1";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractIntegerFromLine(rawOutput, "Lockout threshold");

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
            return CreateErrorEvidence(subControlId, ex);
        }
    }

    private async Task<Evidence> CollectLockoutDuration()
    {
        var subControlId = "LCK-001.2";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractDurationFromLine(rawOutput, "Lockout duration", "minutes");

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
            return CreateErrorEvidence(subControlId, ex);
        }
    }

    private async Task<Evidence> CollectLockoutObservationWindow()
    {
        var subControlId = "LCK-001.3";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "NetAccounts");
            var typedValue = ExtractDurationFromLine(rawOutput, "Lockout observation window", "minutes");

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
            return CreateErrorEvidence(subControlId, ex);
        }
    }

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"LCK-001-{subControlId}",
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

    // =========================================================================
    // Helper methods (keyword-specific parsing from Phase 10.5)
    // =========================================================================

    private static EvidenceValue ExtractIntegerFromLine(string rawOutput, string keyword)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        var lines = rawOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                // Handle "Never" for threshold (means 0 = never lock)
                if (line.Contains("Never", StringComparison.OrdinalIgnoreCase))
                    return EvidenceValue.FromInteger(0);

                var match = Regex.Match(line, @"(\d+)");
                if (match.Success && int.TryParse(match.Groups[1].Value, out var value))
                    return EvidenceValue.FromInteger(value);
            }
        }

        return EvidenceValue.FromInteger(0);
    }

    private static EvidenceValue ExtractDurationFromLine(string rawOutput, string keyword, string unit)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Minutes));

        var lines = rawOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                // Handle "Never" for duration/window (means account stays locked indefinitely)
                // From security perspective, "Never" = very large value, will fail reasonable thresholds
                if (line.Contains("Never", StringComparison.OrdinalIgnoreCase))
                {
                    return EvidenceValue.FromDuration(new DurationValue(99999, DurationUnit.Minutes));
                }

                // Try to extract duration from this line
                var match = Regex.Match(line, @"(\d+)\s*(minutes?|mins?|hours?|days?)", RegexOptions.IgnoreCase);
                if (match.Success && int.TryParse(match.Groups[1].Value, out var durationValue))
                {
                    var durationUnit = match.Groups[2].Value.ToLower() switch
                    {
                        "minute" or "minutes" or "min" or "mins" => DurationUnit.Minutes,
                        "hour" or "hours" => DurationUnit.Hours,
                        "day" or "days" => DurationUnit.Days,
                        _ => DurationUnit.Minutes
                    };
                    return EvidenceValue.FromDuration(new DurationValue(durationValue, durationUnit));
                }

                // Fallback: extract any number from this line (assume minutes)
                var numMatch = Regex.Match(line, @"(\d+)");
                if (numMatch.Success && int.TryParse(numMatch.Groups[1].Value, out var numValue))
                    return EvidenceValue.FromDuration(new DurationValue(numValue, DurationUnit.Minutes));
            }
        }

        return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Minutes));
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