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
/// Phase 12.9: Device Guard & VBS Check (Collector-only pattern).
/// Based on Item 12 from Windows 11 Hardening Guide.
///
/// SubControls (6):
///   - DVG-001.1: EnableVirtualizationBasedSecurity (Registry Integer)
///   - DVG-001.2: RequirePlatformSecurityFeatures (Registry Integer)
///   - DVG-001.3: HypervisorEnforcedCodeIntegrity (Registry Integer)
///   - DVG-001.4: EnableSecureLaunch (Registry Integer)
///   - DVG-001.5: LsaCfgFlags (Registry Integer)
///   - DVG-001.6: VBS Status via Get-CimInstance (String)
/// </summary>
[SupportedOSPlatform("windows")]
public class DeviceGuardCheck : BaseHardeningCheck
{
    private const string DeviceGuardPath = @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public override string CheckId => "DVG-001";
    public override string Name => "Device Guard & VBS";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.Critical;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        // Registry-based settings (5 checks)
        evidenceList.Add(CollectRegistryInteger("DVG-001.1", DeviceGuardPath, "EnableVirtualizationBasedSecurity", startTime));
        evidenceList.Add(CollectRegistryInteger("DVG-001.2", DeviceGuardPath, "RequirePlatformSecurityFeatures", startTime));
        evidenceList.Add(CollectRegistryInteger("DVG-001.3", DeviceGuardPath, "HypervisorEnforcedCodeIntegrity", startTime));
        evidenceList.Add(CollectRegistryInteger("DVG-001.4", DeviceGuardPath, "EnableSecureLaunch", startTime));
        evidenceList.Add(CollectRegistryInteger("DVG-001.5", LsaPath, "LsaCfgFlags", startTime));

        // Runtime VBS status via Get-CimInstance (1 check)
        evidenceList.Add(await CollectVbsStatus("DVG-001.6", startTime));

        return evidenceList;
    }

    private Evidence CollectRegistryInteger(string subControlId, string regPath, string valueName, DateTime startTime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath);
            var value = key?.GetValue(valueName);
            int intValue = value != null ? Convert.ToInt32(value) : -1;
            string rawOutput = value != null ? intValue.ToString() : "Not Configured";

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                AcquisitionCommand = $@"reg query HKLM\{regPath} /v {valueName}",
                RawOutput = rawOutput,
                TypedValue = EvidenceValue.FromInteger(intValue),
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
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromInteger(-1),
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = 0
            };
        }
    }

    private async Task<Evidence> CollectVbsStatus(string subControlId, DateTime startTime)
    {
        string status = "Unknown";
        try
        {
            // Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
            // Returns SecurityServicesRunning property (bitmask)
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -Command \"$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue; if ($dg) { $dg.SecurityServicesRunning } else { 'NotAvailable' }\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                status = string.IsNullOrWhiteSpace(output) ? "NotAvailable" : output.Trim();
            }
        }
        catch (Exception ex)
        {
            status = $"Error: {ex.Message}";
        }

        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.Cim,
            SourceName = "Win32_DeviceGuard",
            AcquisitionCommand = "Get-CimInstance -ClassName Win32_DeviceGuard",
            RawOutput = status,
            TypedValue = EvidenceValue.FromString(status),
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
        };
    }
}