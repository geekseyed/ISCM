using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class PowerShellLoggingCheck : IHardeningCheck, IMultiPathCheck
{
    private const string ScriptBlockPath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
    private const string ModulePath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";

    public string CheckId => "PSH-001";
    public string Name => "PowerShell Script Block Logging";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "PSH-001.1", Title = "Turn on PowerShell Script Block Logging", Expected = "Enabled (Event 4104)",
            WhatItDoes = "Logs the actual script blocks executed by PowerShell.", Recommendation = "EnableScriptBlockLogging = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' | Select EnableScriptBlockLogging",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' | Select EnableScriptBlockLogging",
            Verification = "EnableScriptBlockLogging = 1.", ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name EnableScriptBlockLogging: captures script block content (4104).",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows PowerShell → Script Block Logging",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging > Enabled",
            GraphicalSteps = "1) gpedit.msc → Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell. 2) 'Turn on PowerShell Script Block Logging' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 0",
            IgnoreConsequence = "Malicious PowerShell runs without script-content logging.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows PowerShell." },
        new SubCheck { Id = "PSH-001.2", Title = "Turn on Module Logging", Expected = "Enabled",
            WhatItDoes = "Logs pipeline execution details for specified modules.", Recommendation = "EnableModuleLogging = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' | Select EnableModuleLogging",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' | Select EnableModuleLogging",
            Verification = "EnableModuleLogging = 1.", ValueMap = "1 = Enabled.",
            CliTokens = "-Name EnableModuleLogging: logs module pipeline details.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows PowerShell → Module Logging",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging > Enabled",
            GraphicalSteps = "1) Windows PowerShell node. 2) 'Turn on Module Logging' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Value 0",
            IgnoreConsequence = "Module activity not logged.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows PowerShell." },
        new SubCheck { Id = "PSH-001.3", Title = "Log script block invocation start/stop events (nested option)", Expected = "Enabled (optional)",
            WhatItDoes = "Adds start/stop markers around each executed script block.", Recommendation = "EnableScriptBlockInvocationLogging = 1 (optional; high volume).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' | Select EnableScriptBlockInvocationLogging",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' | Select EnableScriptBlockInvocationLogging",
            Verification = "EnableScriptBlockInvocationLogging = 1.", ValueMap = "1 = Enabled.",
            CliTokens = "-Name EnableScriptBlockInvocationLogging: start/stop markers (4105/4106).",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Script Block Logging dialog → invocation start/stop option",
            GraphicalPathFull = "Same policy dialog as 'Turn on PowerShell Script Block Logging' — it is an option INSIDE that policy, not a separate GPO node",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging (options)",
            YouAreHere = "gpedit.msc → Windows PowerShell → Script Block Logging dialog", GoTo = "Inside the Script Block Logging dialog → check 'Log script block invocation start/stop events'",
            GraphicalSteps = "1) Open 'Turn on PowerShell Script Block Logging'. 2) Inside its options, enable 'Log script block invocation start/stop events'.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -Value 0",
            IgnoreConsequence = "No invocation boundaries in logs (optional feature).", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging",
            AlternativeToRegistry = "Prefer the policy dialog option." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // 1. EnableScriptBlockLogging
            using var sbKey = Registry.LocalMachine.OpenSubKey(ScriptBlockPath);
            var sbVal = sbKey?.GetValue("EnableScriptBlockLogging");
            if (sbVal != null && sbVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. EnableModuleLogging
            using var modKey = Registry.LocalMachine.OpenSubKey(ModulePath);
            var modVal = modKey?.GetValue("EnableModuleLogging");
            if (modVal != null && modVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 3. EnableScriptBlockInvocationLogging (optional, nested)
            var invVal = sbKey?.GetValue("EnableScriptBlockInvocationLogging");
            if (invVal != null && invVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} PowerShell logging settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "Script Block + Module logging enabled",
                "Enable PowerShell script block logging to detect malicious activity.",
                errorMessage: string.Empty,
                description: "Captures the content of PowerShell scripts and commands (Event 4104).",
                registryPath: $@"HKLM\{ScriptBlockPath}\EnableScriptBlockLogging",
                cisReference: "CIS 10.3", riskScore: 55, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{ScriptBlockPath}"" /v EnableScriptBlockLogging",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Captures the content of PowerShell scripts and commands (Event 4104).",
                registryPath: $@"HKLM\{ScriptBlockPath}\EnableScriptBlockLogging",
                cisReference: "CIS 10.3", riskScore: 55, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{ScriptBlockPath}"" /v EnableScriptBlockLogging",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry برای EnableScriptBlockLogging
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ScriptBlockPath);
            if (key != null)
            {
                var v = key.GetValue("EnableScriptBlockLogging");
                if (v != null && v.ToString() == "1")
                {
                    results.Add(new TestResult("Primary", "Registry (ScriptBlockLogging)", true, "EnableScriptBlockLogging = 1"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (ScriptBlockLogging)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (ScriptBlockLogging)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (ScriptBlockLogging)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: Registry برای EnableModuleLogging
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ModulePath);
            if (key != null)
            {
                var v = key.GetValue("EnableModuleLogging");
                if (v != null && v.ToString() == "1")
                {
                    results.Add(new TestResult("Cross-check", "Registry (ModuleLogging)", true, "EnableModuleLogging = 1"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Registry (ModuleLogging)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry (ModuleLogging)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry (ModuleLogging)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: PowerShell Get-WinEvent برای بررسی event 4104
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated\"")
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
                var passed = !string.IsNullOrWhiteSpace(output);
                var details = passed ? $"Last ScriptBlock event: {output.Trim()}" : "No recent ScriptBlock events (logging may not be active)";
                results.Add(new TestResult("Verification", "Get-WinEvent (4104)", passed, details));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Get-WinEvent (4104)", false, $"Error: {ex.Message}"));
        }
        return results;
    }

    private static CheckStatus GetWorstStatus(IEnumerable<CheckStatus> statuses)
    {
        if (statuses.Any(s => s == CheckStatus.Fail)) return CheckStatus.Fail;
        if (statuses.Any(s => s == CheckStatus.Error)) return CheckStatus.Error;
        if (statuses.Any(s => s == CheckStatus.Unknown)) return CheckStatus.Unknown;
        return CheckStatus.Pass;
    }
}