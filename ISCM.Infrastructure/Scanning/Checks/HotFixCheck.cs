using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 12.1: HotFix Currency Check (Collector-only pattern).
/// 
/// SubControls (5):
///   - HFX-001.1: Has any hotfix (Boolean)
///   - HFX-001.2: Days since latest hotfix (Duration)
///   - HFX-001.3: Total hotfix count (Integer)
///   - HFX-001.4: Latest KB ID (String)
///   - HFX-001.5: Latest install date (String)
/// </summary>
[SupportedOSPlatform("windows")]
public class HotFixCheck : BaseHardeningCheck
{
    public override string CheckId => "HFX-001";
    public override string Name => "HotFix Currency";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        try
        {
            // Single optimized PowerShell script returning JSON
            string psScript = @"
                $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
                $count = ($hotfixes | Measure-Object).Count
                $latest = $hotfixes | Select-Object -First 1
                $latestKb = if ($latest) { $latest.HotFixID } else { 'None' }
                $latestDate = if ($latest -and $latest.InstalledOn) { $latest.InstalledOn.ToString('yyyy-MM-dd') } else { '1970-01-01' }
                $daysSince = if ($latest -and $latest.InstalledOn) { [math]::Round(((Get-Date) - $latest.InstalledOn).TotalDays, 2) } else { 99999 }
                $hasAny = $count -gt 0

                [PSCustomObject]@{
                    HasAny = $hasAny
                    TotalCount = $count
                    LatestKB = $latestKb
                    LatestDate = $latestDate
                    DaysSince = $daysSince
                } | ConvertTo-Json -Compress
            ";

            string rawOutput = await RunPowerShellAsync(psScript);
            var durationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

            // Parse JSON safely
            using var doc = JsonDocument.Parse(rawOutput);
            var root = doc.RootElement;

            bool hasAny = root.GetProperty("HasAny").GetBoolean();
            int totalCount = root.GetProperty("TotalCount").GetInt32();
            string latestKb = root.GetProperty("LatestKB").GetString() ?? "None";
            string latestDate = root.GetProperty("LatestDate").GetString() ?? "1970-01-01";
            double daysSince = root.GetProperty("DaysSince").GetDouble();

            // 1. HFX-001.1: Has Any (Boolean)
            evidenceList.Add(CreateEvidence("HFX-001.1", "Get-HotFix Count", rawOutput,
                EvidenceValue.FromBoolean(hasAny), durationMs));

            // 2. HFX-001.2: Days Since (Duration)
            evidenceList.Add(CreateEvidence("HFX-001.2", "Get-HotFix Latest Date", rawOutput,
                EvidenceValue.FromDuration(new DurationValue((long)daysSince, DurationUnit.Days)), durationMs));

            // 3. HFX-001.3: Total Count (Integer)
            evidenceList.Add(CreateEvidence("HFX-001.3", "Get-HotFix Count", rawOutput,
                EvidenceValue.FromInteger(totalCount), durationMs));

            // 4. HFX-001.4: Latest KB (String)
            evidenceList.Add(CreateEvidence("HFX-001.4", "Get-HotFix Latest KB", rawOutput,
                EvidenceValue.FromString(latestKb), durationMs));

            // 5. HFX-001.5: Latest Date (String)
            evidenceList.Add(CreateEvidence("HFX-001.5", "Get-HotFix Latest Date", rawOutput,
                EvidenceValue.FromString(latestDate), durationMs));
        }
        catch (Exception ex)
        {
            // Fallback for all subcontrols on critical failure
            var fallbackRaw = $"Exception: {ex.Message}";
            evidenceList.Add(CreateFallback("HFX-001.1", fallbackRaw, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("HFX-001.2", fallbackRaw, EvidenceValue.FromDuration(new DurationValue(99999, DurationUnit.Days))));
            evidenceList.Add(CreateFallback("HFX-001.3", fallbackRaw, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("HFX-001.4", fallbackRaw, EvidenceValue.FromString("Error")));
            evidenceList.Add(CreateFallback("HFX-001.5", fallbackRaw, EvidenceValue.FromString("Error")));
        }

        return evidenceList;
    }

    private Evidence CreateEvidence(string subControlId, string sourceName, string rawOutput, EvidenceValue typedValue, int durationMs)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = sourceName,
            AcquisitionCommand = "Get-HotFix | Sort-Object InstalledOn -Descending",
            RawOutput = rawOutput,
            TypedValue = typedValue,
            Evaluation = CheckStatus.NotScanned, // Mandatory Phase 11.5 rule
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = durationMs
        };
    }

    private Evidence CreateFallback(string subControlId, string rawOutput, EvidenceValue typedValue)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-HotFix",
            RawOutput = rawOutput,
            TypedValue = typedValue,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = 0
        };
    }

    private static async Task<string> RunPowerShellAsync(string command)
    {
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -Command \"{command}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return "{\"HasAny\":false,\"TotalCount\":0,\"LatestKB\":\"Error\",\"LatestDate\":\"1970-01-01\",\"DaysSince\":99999}";

        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        return string.IsNullOrWhiteSpace(output) ? "{\"HasAny\":false,\"TotalCount\":0,\"LatestKB\":\"None\",\"LatestDate\":\"1970-01-01\",\"DaysSince\":99999}" : output;
    }
}