using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class DisableCmdCheck : IHardeningCheck
{
    private const string RegPath = @"SOFTWARE\Policies\Microsoft\Windows\System";
    private const string ValueName = "DisableCMD";

    public string CheckId => "CMD-001";
    public string Name => "Disable CMD & Script Execution";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "CMD-001.1", Title = "Prevent access to the command prompt", Expected = "Enabled",
            WhatItDoes = "Disables cmd.exe for standard users.",
            Recommendation = "Set DisableCMD = 1 (or 2 to also block scripts).",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 2 -Type DWord",
            Verification = "Get-ItemProperty '...\\Windows\\System' → DisableCMD = 2.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "System → Prevent access to command prompt",
            YouAreHere = "Registry Editor (root)", GoTo = "Policies\\Microsoft\\Windows\\System → DisableCMD = 2",
            GraphicalSteps = "1) gpedit → User Config → System. 2) 'Prevent access to the command prompt' = Enabled.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD",
            AlternativeToRegistry = "Prefer gpedit.msc → System over manual registry editing." },
        new SubCheck { Id = "CMD-001.2", Title = "Disable command prompt script processing also", Expected = "Yes",
            WhatItDoes = "Blocks .bat/.cmd script execution, not just interactive CMD.",
            Recommendation = "Use DisableCMD = 2 (includes script blocking).",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 2 -Type DWord",
            Verification = "DisableCMD = 2 means scripts are also blocked.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "System → Disable script processing = Yes",
            YouAreHere = "Registry Editor (root)", GoTo = "Windows\\System → DisableCMD = 2",
            GraphicalSteps = "1) In the same policy set 'Disable…script processing also?' = Yes.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD",
            AlternativeToRegistry = "Prefer gpedit.msc → System over manual registry editing." },
        new SubCheck { Id = "CMD-001.3", Title = "Don't run specified Windows applications (optional)", Expected = "cmd.exe, powershell.exe for non-admins",
            WhatItDoes = "Adds an extra layer blocking specific executables for non-admins.",
            Recommendation = "Add cmd.exe/powershell.exe to the disallowed list for standard users.",
            CliCommand = "# gpedit → User Config → System → Don't run specified Windows applications → add cmd.exe",
            Verification = "gpedit → 'Don't run specified Windows applications' lists cmd.exe.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "System → Don't run specified applications",
            YouAreHere = "Group Policy (root)", GoTo = "User Config → System → Don't run specified Windows applications",
            GraphicalSteps = "1) Enable policy. 2) Add cmd.exe (and powershell.exe for non-admins).",
            HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            var v = key?.GetValue(ValueName);
            if (v != null && (v.ToString() == "1" || v.ToString() == "2")) { currentValue = "Disabled"; status = CheckStatus.Pass; }
            else { currentValue = "Enabled"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue,
            "Disabled", "Block cmd.exe and batch scripts for standard users to reduce attack surface.",
            errorMessage: errorMessage,
            description: "Blocks standard users from running cmd.exe and batch scripts.",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 2.9", riskScore: 50, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" }, subChecks: SubChecks));
    }
}