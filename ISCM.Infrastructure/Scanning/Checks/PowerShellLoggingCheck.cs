using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class PowerShellLoggingCheck : IHardeningCheck
{
    private const string RegPath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
    private const string ValueName = "EnableScriptBlockLogging";

    public string CheckId => "PSH-001";
    public string Name => "PowerShell Script Block Logging";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    // Revised PDF item 6: third setting is NESTED inside the Script Block Logging dialog.
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
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > 'Turn on PowerShell Script Block Logging' > Enabled",
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
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > 'Turn on Module Logging' > Enabled",
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
            YouAreHere = "gpedit.msc → Windows PowerShell → Script Block Logging dialog", GoTo = "Same Policy dialog as 'Turn on Powershell Script Block Logging' -- it is an option unside that policy, not a separate standalone GPO node",
            GraphicalSteps = "1) Open 'Turn on PowerShell Script Block Logging'. 2) Inside its options, enable 'Log script block invocation start/stop events'.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -Value 0",
            IgnoreConsequence = "No invocation boundaries in logs (optional feature).", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging",
            AlternativeToRegistry = "Prefer the policy dialog option." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            var v = key?.GetValue(ValueName);
            if (v != null && v.ToString() == "1") { currentValue = "Enabled"; status = CheckStatus.Pass; }
            else { currentValue = "Disabled"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Enabled", "Enable PowerShell script block logging to detect malicious activity.",
            errorMessage: errorMessage,
            description: "Captures the content of PowerShell scripts and commands (Event 4104).",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 10.3", riskScore: 55, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }
}