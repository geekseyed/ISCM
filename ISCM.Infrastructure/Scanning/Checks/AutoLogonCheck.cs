using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 11.4: AutoLogonCheck migrated to Collector-only pattern.
/// 
/// Verifies automatic logon is disabled:
/// - ALG-001.1: Automatic logon disabled (AutoAdminLogon = 0)
/// 
/// Produces Evidence with TypedValue = bool for each SubControl.
/// Scanner will evaluate using catalog metadata (ExpectedValueType.Boolean, Operator.Equals, Expected="Disabled").
/// </summary>
[SupportedOSPlatform("windows")]
public class AutoLogonCheck : BaseHardeningCheck
{
    private const string WinlogonRegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string AutoAdminLogonValueName = "AutoAdminLogon";
    private const string DefaultPasswordValueName = "DefaultPassword";

    public override string CheckId => "ALG-001";
    public override string Name => "AutoLogon Disabled";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // ALG-001.1: Automatic logon disabled
        var autoLogonDisabled = await GetAutoLogonDisabled();
        evidenceList.Add(CreateEvidence(
            subControlId: "ALG-001.1",
            pathId: "ALG-001.1-path-1",
            sourceType: EvidenceSourceType.Registry,
            sourceName: "Registry (AutoAdminLogon)",
            command: $@"reg query ""HKLM\{WinlogonRegistryPath}"" /v {AutoAdminLogonValueName}",
            rawOutput: $"AutoAdminLogon = {(autoLogonDisabled ? "0 (Disabled)" : "1 (Enabled)")}",
            typedValue: autoLogonDisabled
        ));

        // Additional evidence: Check for DefaultPassword (security risk)
        var hasDefaultPassword = await CheckDefaultPassword();
        if (hasDefaultPassword)
        {
            evidenceList.Add(CreateEvidence(
                subControlId: "ALG-001.1",
                pathId: "ALG-001.1-path-2",
                sourceType: EvidenceSourceType.Registry,
                sourceName: "Registry (DefaultPassword)",
                command: $@"reg query ""HKLM\{WinlogonRegistryPath}"" /v {DefaultPasswordValueName}",
                rawOutput: "DefaultPassword value found (credential stored in plaintext)",
                typedValue: false // Presence of DefaultPassword is a security risk
            ));
        }

        return evidenceList;
    }

    private async Task<bool> GetAutoLogonDisabled()
    {
        try
        {
            // Method 1: Registry check
            using var key = Registry.LocalMachine.OpenSubKey(WinlogonRegistryPath);
            if (key != null)
            {
                var value = key.GetValue(AutoAdminLogonValueName);
                if (value != null && int.TryParse(value.ToString(), out int val))
                {
                    return val == 0; // 0 = Disabled, 1 = Enabled
                }
            }

            // Method 2: PowerShell fallback
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'AutoAdminLogon' -ErrorAction Stop | Select-Object -ExpandProperty AutoAdminLogon\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return true; // Default: assume disabled

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                if (int.TryParse(output.Trim(), out int val))
                {
                    return val == 0;
                }
            }

            return true; // Default: assume disabled if not explicitly enabled
        }
        catch
        {
            return true; // Default: assume disabled on error
        }
    }

    private async Task<bool> CheckDefaultPassword()
    {
        try
        {
            // Check if DefaultPassword exists (security risk)
            using var key = Registry.LocalMachine.OpenSubKey(WinlogonRegistryPath);
            if (key != null)
            {
                var value = key.GetValue(DefaultPasswordValueName);
                if (value != null && !string.IsNullOrWhiteSpace(value.ToString()))
                {
                    return true; // DefaultPassword exists
                }
            }

            // PowerShell fallback
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DefaultPassword\"")
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

            return !string.IsNullOrWhiteSpace(output);
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