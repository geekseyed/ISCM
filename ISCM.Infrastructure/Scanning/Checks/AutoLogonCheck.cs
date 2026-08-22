using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AutoLogonCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string ValueName = "AutoAdminLogon";

    public string CheckId => "ALG-001";
    public string Name => "AutoLogon Disabled";
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
                var val = key.GetValue(ValueName);
                if (val != null && val.ToString() == "0")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Registry Key Missing";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        // EDIT (مرحله د): تغذیه متادیتای واقعی
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Disabled",
            recommendation: "Disable AutoLogon to require credential entry upon boot.",
            errorMessage: errorMessage,
            description: "AutoLogon stores credentials in plaintext in the registry and enables unauthorized system access without authentication.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 2.3.11.1",
            riskScore: 40,
            sourceType: "RegistryReader",
            sourceCommand: $"reg query \"HKLM\\{RegistryPath}\" /v {ValueName}",
            fixTools: new List<string> { "regedit.exe" }
        ));
    }

    // EDIT (فاز 1 - پیام 2): سه تست واقعی برای AutoLogon
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry AutoAdminLogon (اصلی - همان EvaluateAsync)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    // 0 = Disabled (pass), 1 = Enabled (fail)
                    var passed = val == 0;
                    results.Add(new TestResult(
                        "Primary",
                        "Registry (AutoAdminLogon)",
                        passed,
                        $"AutoAdminLogon = {val}"));
                }
                else
                {
                    // Value not set = not configured (treat as pass since no auto-logon)
                    results.Add(new TestResult(
                        "Primary",
                        "Registry (AutoAdminLogon)",
                        true,
                        "AutoAdminLogon not set (default = Disabled)"));
                }
            }
            else
            {
                results.Add(new TestResult(
                    "Primary",
                    "Registry (AutoAdminLogon)",
                    true,
                    "Winlogon registry key not found (default = Disabled)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Primary",
                "Registry (AutoAdminLogon)",
                false,
                $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Registry DefaultPassword (خطر امنیتی - credential ذخیره شده)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue("DefaultPassword");
                if (v != null && !string.IsNullOrWhiteSpace(v.ToString()))
                {
                    // Password stored in registry = security risk (fail)
                    results.Add(new TestResult(
                        "Cross-check",
                        "Registry (DefaultPassword)",
                        false,
                        "DefaultPassword value found (credential stored in plaintext)"));
                }
                else
                {
                    results.Add(new TestResult(
                        "Cross-check",
                        "Registry (DefaultPassword)",
                        true,
                        "DefaultPassword not set (no plaintext credential stored)"));
                }
            }
            else
            {
                results.Add(new TestResult(
                    "Cross-check",
                    "Registry (DefaultPassword)",
                    true,
                    "Winlogon key not found (no credential risk)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Cross-check",
                "Registry (DefaultPassword)",
                false,
                $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: PowerShell Get-ItemProperty برای Winlogon (بررسی DefaultUserName)
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'DefaultUserName','AutoAdminLogon' -ErrorAction SilentlyContinue | Select-Object -Property DefaultUserName,AutoAdminLogon | ConvertTo-Json -Compress\"")
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
                    var hasAutoLogon = output.Contains("\"AutoAdminLogon\":1") || output.Contains("\"AutoAdminLogon\": \"1\"");
                    var hasUser = output.Contains("DefaultUserName");
                    var passed = !hasAutoLogon;
                    results.Add(new TestResult(
                        "Verification",
                        "PowerShell (Winlogon properties)",
                        passed,
                        hasAutoLogon ? "AutoAdminLogon=1 detected" : "AutoAdminLogon not enabled"));
                }
                else
                {
                    results.Add(new TestResult(
                        "Verification",
                        "PowerShell (Winlogon properties)",
                        true,
                        "Winlogon properties not found (default safe state)"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Verification",
                "PowerShell (Winlogon properties)",
                false,
                $"Error: {ex.Message}"));
        }

        return results;
    }
}