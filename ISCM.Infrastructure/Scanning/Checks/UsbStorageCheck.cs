using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 11.3: UsbStorageCheck migrated to Collector-only pattern.
/// 
/// Verifies USB storage is restricted:
/// - USB-001.1: USB storage device access restricted (USBSTOR\Start = 4)
/// 
/// Produces Evidence with TypedValue = bool for each SubControl.
/// Scanner will evaluate using catalog metadata (ExpectedValueType.Boolean, Operator.Equals, Expected="Enabled").
/// </summary>
[SupportedOSPlatform("windows")]
public class UsbStorageCheck : BaseHardeningCheck
{
    private const string UsbStorRegistryPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string UsbStorValueName = "Start";
    private const string PolicyRegistryPath = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDeny";

    public override string CheckId => "USB-001";
    public override string Name => "USB Storage Policy";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // USB-001.1: USB storage device access restricted
        var usbRestricted = await GetUsbStorageRestricted();
        evidenceList.Add(CreateEvidence(
            subControlId: "USB-001.1",
            pathId: "USB-001.1-path-1",
            sourceType: EvidenceSourceType.Registry,
            sourceName: "Registry (USBSTOR\\Start)",
            command: $@"reg query ""HKLM\{UsbStorRegistryPath}"" /v {UsbStorValueName}",
            rawOutput: $"USBSTOR\\Start = {(usbRestricted ? "4 (Disabled/Restricted)" : "Not 4 (Allowed)")}",
            typedValue: usbRestricted
        ));

        return evidenceList;
    }

    private async Task<bool> GetUsbStorageRestricted()
    {
        try
        {
            // Method 1: Registry USBSTOR\Start
            using var key = Registry.LocalMachine.OpenSubKey(UsbStorRegistryPath);
            if (key != null)
            {
                var value = key.GetValue(UsbStorValueName);
                if (value != null && int.TryParse(value.ToString(), out int val))
                {
                    return val == 4; // 4 = Disabled (Restricted), 2/3 = Enabled (Allowed)
                }
            }

            // Method 2: PowerShell fallback
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -ErrorAction Stop | Select-Object -ExpandProperty Start\"")
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
                if (int.TryParse(output.Trim(), out int val))
                {
                    return val == 4;
                }
            }

            // Method 3: Check RemovableStorageDeny policy
            using var policyKey = Registry.LocalMachine.OpenSubKey(PolicyRegistryPath);
            if (policyKey != null)
            {
                var denyRead = policyKey.GetValue("Deny_Read");
                var denyWrite = policyKey.GetValue("Deny_Write");
                var denyExecute = policyKey.GetValue("Deny_Execute");

                // If any deny policy is set, consider USB restricted
                if (denyRead != null || denyWrite != null || denyExecute != null)
                {
                    return true;
                }
            }

            return false; // Default: USB storage allowed
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