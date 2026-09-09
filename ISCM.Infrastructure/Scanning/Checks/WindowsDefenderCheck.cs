using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 11.2: WindowsDefenderCheck migrated to Collector-only pattern.
/// 
/// Verifies Windows Defender is enabled and configured properly:
/// - DEF-001.1: Antivirus enabled (AMServiceEnabled)
/// - DEF-001.2: Real-time protection enabled (DisableRealtimeMonitoring = 0)
/// - DEF-001.3: Antivirus definitions up-to-date (AntivirusSignatureUpdateTime)
/// 
/// Produces Evidence with TypedValue = bool for each SubControl.
/// Scanner will evaluate using catalog metadata (ExpectedValueType.Boolean, Operator.Equals, Expected="Enabled").
/// </summary>
[SupportedOSPlatform("windows")]
public class WindowsDefenderCheck : BaseHardeningCheck
{
    private const string DefenderRegistryPath = @"SOFTWARE\Microsoft\Windows Defender";
    private const string RealTimeProtectionPath = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";

    public override string CheckId => "DEF-001";
    public override string Name => "Windows Defender";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // DEF-001.1: Antivirus enabled
        var antivirusEnabled = await GetAntivirusEnabled();
        evidenceList.Add(CreateEvidence(
            subControlId: "DEF-001.1",
            pathId: "DEF-001.1-path-1",
            sourceType: EvidenceSourceType.PowerShell,
            sourceName: "Get-MpComputerStatus",
            command: "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled",
            rawOutput: $"AMServiceEnabled = {antivirusEnabled}",
            typedValue: antivirusEnabled
        ));

        // DEF-001.2: Real-time protection enabled
        var realTimeProtectionEnabled = await GetRealTimeProtectionEnabled();
        evidenceList.Add(CreateEvidence(
            subControlId: "DEF-001.2",
            pathId: "DEF-001.2-path-1",
            sourceType: EvidenceSourceType.Registry,
            sourceName: "Registry (DisableRealtimeMonitoring)",
            command: $@"reg query ""HKLM\{RealTimeProtectionPath}"" /v DisableRealtimeMonitoring",
            rawOutput: $"DisableRealtimeMonitoring = {(realTimeProtectionEnabled ? "0 (Enabled)" : "1 (Disabled)")}",
            typedValue: realTimeProtectionEnabled
        ));

        // DEF-001.3: Antivirus definitions up-to-date
        var definitionsUpToDate = await GetDefinitionsUpToDate();
        evidenceList.Add(CreateEvidence(
            subControlId: "DEF-001.3",
            pathId: "DEF-001.3-path-1",
            sourceType: EvidenceSourceType.PowerShell,
            sourceName: "Get-MpComputerStatus",
            command: "Get-MpComputerStatus | Select-Object AntivirusSignatureUpdateTime",
            rawOutput: $"Definitions up-to-date = {definitionsUpToDate}",
            typedValue: definitionsUpToDate
        ));

        return evidenceList;
    }

    private async Task<bool> GetAntivirusEnabled()
    {
        try
        {
            // Method 1: PowerShell Get-MpComputerStatus
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-MpComputerStatus -ErrorAction Stop | Select-Object -ExpandProperty AMServiceEnabled\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> GetRealTimeProtectionEnabled()
    {
        try
        {
            // Method 1: Registry check
            using var key = Registry.LocalMachine.OpenSubKey(RealTimeProtectionPath);
            if (key != null)
            {
                var value = key.GetValue("DisableRealtimeMonitoring");
                if (value != null && int.TryParse(value.ToString(), out int val))
                {
                    return val == 0; // 0 = Enabled, 1 = Disabled
                }
            }

            // Method 2: PowerShell fallback
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-MpComputerStatus -ErrorAction Stop | Select-Object -ExpandProperty RealTimeProtectionEnabled\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }

            return true; // Default to enabled if not explicitly disabled
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> GetDefinitionsUpToDate()
    {
        try
        {
            // Check if definitions were updated in the last 7 days
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"$status = Get-MpComputerStatus -ErrorAction Stop; $lastUpdate = $status.AntivirusSignatureUpdateTime; $daysAgo = ((Get-Date) - $lastUpdate).TotalDays; Write-Output ([math]::Round($daysAgo, 2))\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                if (double.TryParse(output.Trim(), out double daysAgo))
                {
                    return daysAgo <= 7.0; // Consider up-to-date if updated within last 7 days
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private Evidence CreateEvidence(
        string subControlId,
        string pathId,
        EvidenceSourceType sourceType,
        string sourceName,
        string command,
        string rawOutput,
        bool typedValue)
    {
        var evidence = new Evidence
        {
            SubControlId = subControlId,
            PathId = pathId,
            SourceType = sourceType,
            SourceName = sourceName,
            AcquisitionCommand = command,
            RawOutput = rawOutput,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };

        evidence.TypedValue = new EvidenceValue(
            value: typedValue,
            type: EvidenceValueType.Boolean,
            unit: null,
            rawString: typedValue.ToString()
        );

        return evidence;
    }
}