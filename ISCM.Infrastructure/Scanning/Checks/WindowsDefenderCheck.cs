using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class WindowsDefenderCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    private const string ValueName = "DisableRealtimeMonitoring";

    public string CheckId => "DEF-001";
    public string Name => "Windows Defender";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var registryValue = key.GetValue(ValueName);
                if (registryValue != null && registryValue.ToString() == "1")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Pass;
                }
            }
            else
            {
                currentValue = "Registry Key Missing";
                status = CheckStatus.Unknown; // اصلاح شد
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Enabled",
            recommendation: "Enable Windows Defender real-time protection.",
            errorMessage: errorMessage,
            description: "Windows Defender real-time protection must be enabled to detect and block malware in real time.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 1.2",
            riskScore: 88,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe" }
        ));
    }

    // EDIT (فاز 1 - پیام 2): سه تست واقعی برای Windows Defender
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry HKLM - DisableRealtimeMonitoring
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    // 0 = Enabled (good), 1 = Disabled (bad)
                    var passed = val == 0;
                    results.Add(new TestResult(
                        "Primary",
                        "Registry (DisableRealtimeMonitoring)",
                        passed,
                        $"DisableRealtimeMonitoring = {val} ({(passed ? "Enabled" : "Disabled")})"));
                }
                else
                {
                    // Value missing = Enabled by default (Windows Defender default state)
                    results.Add(new TestResult(
                        "Primary",
                        "Registry (DisableRealtimeMonitoring)",
                        true,
                        "Value not set (default = Enabled)"));
                }
            }
            else
            {
                results.Add(new TestResult(
                    "Primary",
                    "Registry (DisableRealtimeMonitoring)",
                    true,
                    "Registry key not found (default = Enabled)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Primary",
                "Registry (DisableRealtimeMonitoring)",
                false,
                $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: PowerShell Get-MpComputerStatus - RealTimeProtectionEnabled
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-Command \"Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RealTimeProtectionEnabled\"")
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

                if (!string.IsNullOrWhiteSpace(output))
                {
                    var passed = output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
                    results.Add(new TestResult(
                        "Cross-check",
                        "Get-MpComputerStatus (RealTimeProtection)",
                        passed,
                        $"RealTimeProtectionEnabled = {output.Trim()}"));
                }
                else
                {
                    results.Add(new TestResult(
                        "Cross-check",
                        "Get-MpComputerStatus (RealTimeProtection)",
                        false,
                        "Could not query RealTimeProtectionEnabled"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Cross-check",
                "Get-MpComputerStatus (RealTimeProtection)",
                false,
                $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: PowerShell Get-MpComputerStatus - AMRunningMode
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-Command \"Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AMRunningMode\"")
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

                if (!string.IsNullOrWhiteSpace(output))
                {
                    // AMRunningMode: "Normal" = active, "Passive" = not enforcing, "EDR Blocked" = disabled
                    var mode = output.Trim();
                    var passed = mode.Equals("Normal", StringComparison.OrdinalIgnoreCase);
                    results.Add(new TestResult(
                        "Verification",
                        "Get-MpComputerStatus (AMRunningMode)",
                        passed,
                        $"AMRunningMode = {mode}"));
                }
                else
                {
                    results.Add(new TestResult(
                        "Verification",
                        "Get-MpComputerStatus (AMRunningMode)",
                        false,
                        "Could not query AMRunningMode"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Verification",
                "Get-MpComputerStatus (AMRunningMode)",
                false,
                $"Error: {ex.Message}"));
        }

        return results;
    }
}