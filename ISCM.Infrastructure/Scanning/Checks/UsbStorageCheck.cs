using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class UsbStorageCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string ValueName = "Start";

    public string CheckId => "USB-001";
    public string Name => "USB Storage Policy";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = string.Empty;
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var val = key.GetValue(ValueName);
                if (val != null && val.ToString() == "4")
                {
                    currentValue = "Restricted";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Allowed";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Registry Key Missing";
                status = CheckStatus.Unknown; // ✅ اصلاح: Warning → Unknown
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Restricted",
            recommendation: "Restrict USB storage devices to prevent malware spread.",
            errorMessage: errorMessage,
            description: "USB storage must be restricted to prevent data exfiltration and malware introduction via removable media.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 10.2",
            riskScore: 80,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "regedit.exe", "gpedit.msc" }
        ));
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry USBSTOR\Start
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 4;
                    var desc = val switch
                    {
                        2 => "Automatic (Allowed)",
                        3 => "Manual (Allowed)",
                        4 => "Disabled (Restricted)",
                        _ => $"Unknown ({val})"
                    };
                    results.Add(new TestResult("Primary", "Registry (USBSTOR\\Start)", passed, $"Start = {val} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (USBSTOR\\Start)", false, "Start value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (USBSTOR\\Start)", false, "USBSTOR registry key not found (USB storage enabled by default)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (USBSTOR\\Start)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: PowerShell Get-ItemProperty
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start\"")
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
                if (!string.IsNullOrWhiteSpace(output) && int.TryParse(output.Trim(), out int val))
                {
                    var passed = val == 4;
                    results.Add(new TestResult("Cross-check", "PowerShell (USBSTOR Start)", passed, $"Start = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "PowerShell (USBSTOR Start)", false, "Could not query USBSTOR Start via PowerShell"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "PowerShell (USBSTOR Start)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: Registry Policy layer - RemovableStorageDeny
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDeny");
            if (key != null)
            {
                var denyRead = key.GetValue("Deny_Read");
                var denyWrite = key.GetValue("Deny_Write");
                var denyExecute = key.GetValue("Deny_Execute");
                var hasPolicy = denyRead != null || denyWrite != null || denyExecute != null;
                var passed = hasPolicy;
                var details = hasPolicy ? $"RemovableStorageDeny policy active (Read={denyRead ?? 0}, Write={denyWrite ?? 0}, Exec={denyExecute ?? 0})" : "No RemovableStorageDeny policy configured";
                results.Add(new TestResult("Verification", "Registry (RemovableStorageDeny policy)", passed, details));
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (RemovableStorageDeny policy)", false, "RemovableStorageDeny policy not configured (USB storage allowed by policy)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (RemovableStorageDeny policy)", false, $"Error: {ex.Message}"));
        }
        return results;
    }
}