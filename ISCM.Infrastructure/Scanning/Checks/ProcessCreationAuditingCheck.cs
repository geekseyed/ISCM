using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class ProcessCreationAuditingCheck : IHardeningCheck
{
    private const string RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string ValueName = "ProcessCreationIncludeCmdLine_Enabled";

    public string CheckId => "PRC-001";
    public string Name => "Process Creation Auditing";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "PRC-001.1", Title = "Audit Process Creation", Expected = "Success (Event 4688)",
            WhatItDoes = "Logs every new process started on the system.",
            Recommendation = "Enable success auditing for Process Creation.",
            CliCommand = "auditpol /set /subcategory:\"Process Creation\" /success:enable",
            Verification = "Run: auditpol /get /subcategory:\"Process Creation\" → Success enabled.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Detailed Tracking → Process Creation",
            YouAreHere = "Audit Policy (root)", GoTo = "Advanced Audit → Detailed Tracking → Process Creation → Success",
            GraphicalSteps = "1) Advanced Audit Policy → Detailed Tracking. 2) 'Audit Process Creation' → Success.",
            HasRegistryPath = false },
        new SubCheck { Id = "PRC-001.2", Title = "Include command line in process creation events", Expected = "Enabled",
            WhatItDoes = "Adds the full command line to Event 4688 for forensic detail.",
            Recommendation = "Set ProcessCreationIncludeCmdLine_Enabled = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord",
            Verification = "Get-ItemProperty '...\\System\\Audit' → ProcessCreationIncludeCmdLine_Enabled = 1.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "System → Audit Process Creation → Include cmdline",
            YouAreHere = "Registry Editor (root)", GoTo = "Policies\\System\\Audit → ProcessCreationIncludeCmdLine_Enabled = 1",
            GraphicalSteps = "1) gpedit → System → Audit Process Creation. 2) 'Include command line…' = Enabled.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled",
            AlternativeToRegistry = "Prefer gpedit.msc → System → Audit Process Creation over manual registry editing." }
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
            "Enabled", "Enable process-creation auditing with command-line capture for forensic visibility.",
            errorMessage: errorMessage,
            description: "Records every new process along with its full command line (Event 4688).",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 10.2", riskScore: 55, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" }, subChecks: SubChecks));
    }
}