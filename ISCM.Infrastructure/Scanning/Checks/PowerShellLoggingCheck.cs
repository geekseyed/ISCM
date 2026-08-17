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

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "PSH-001.1", Title = "Turn on PowerShell Script Block Logging", Expected = "Enabled (Event 4104)",
            WhatItDoes = "Logs the actual script blocks executed by PowerShell.",
            Recommendation = "Set EnableScriptBlockLogging = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord",
            Verification = "Get-ItemProperty '...\\ScriptBlockLogging' → EnableScriptBlockLogging = 1.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows PowerShell → Script Block Logging",
            YouAreHere = "Registry Editor (root)", GoTo = "PowerShell\\ScriptBlockLogging → EnableScriptBlockLogging = 1",
            GraphicalSteps = "1) gpedit → Windows Components → Windows PowerShell. 2) 'Turn on Script Block Logging' = Enabled.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows PowerShell over manual registry editing." },
        new SubCheck { Id = "PSH-001.2", Title = "Turn on Module Logging", Expected = "Enabled",
            WhatItDoes = "Logs pipeline execution details for specified modules.",
            Recommendation = "Set EnableModuleLogging = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Value 1 -Type DWord",
            Verification = "Get-ItemProperty '...\\ModuleLogging' → EnableModuleLogging = 1.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows PowerShell → Module Logging",
            YouAreHere = "Registry Editor (root)", GoTo = "PowerShell\\ModuleLogging → EnableModuleLogging = 1",
            GraphicalSteps = "1) 'Turn on Module Logging' = Enabled.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows PowerShell over manual registry editing." },
        new SubCheck { Id = "PSH-001.3", Title = "Log script block invocation start/stop", Expected = "Enabled (optional)",
            WhatItDoes = "Adds start/stop markers around each executed script block.",
            Recommendation = "Set EnableScriptBlockInvocationLogging = 1 (optional).",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → EnableScriptBlockInvocationLogging = 1.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows PowerShell → Invocation logging",
            YouAreHere = "Registry Editor (root)", GoTo = "ScriptBlockLogging → EnableScriptBlockInvocationLogging = 1",
            GraphicalSteps = "1) 'Log script block invocation start/stop' = Enabled.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows PowerShell over manual registry editing." }
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

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue,
            "Enabled", "Enable PowerShell script block logging to detect malicious activity.",
            errorMessage: errorMessage,
            description: "Captures the content of PowerShell scripts and commands (Event 4104).",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 10.3", riskScore: 55, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" }, subChecks: SubChecks));
    }
}