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

    // Revised PDF item 9: policy lives under USER Configuration > Admin Templates > System.
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "CMD-001.1", Title = "Prevent access to the command prompt", Expected = "Enabled",
            WhatItDoes = "Disables cmd.exe for targeted (standard) users.", Recommendation = "DisableCMD = 1 or 2.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 2 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            Verification = "DisableCMD = 1 or 2.", ValueMap = "1 = disable CMD only, 2 = disable CMD + scripts.",
            CliTokens = "-Name DisableCMD: blocks cmd.exe; value 2 also blocks script processing.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "User Config → System → Prevent access to the command prompt",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Prevent access to the command prompt",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc (root)", GoTo = "User Configuration > Administrative Templates > System > 'Prevent access to the command prompt' > Enabled",
            GraphicalSteps = "1) gpedit.msc → USER Configuration → Administrative Templates → System. 2) 'Prevent access to the command prompt' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 0",
            IgnoreConsequence = "Standard users keep interactive CMD.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD",
            AlternativeToRegistry = "Prefer gpedit.msc → User Configuration → System." },
        new SubCheck { Id = "CMD-001.2", Title = "Disable the command prompt script processing also (policy option)", Expected = "Yes",
            WhatItDoes = "Blocks .bat/.cmd execution, not just interactive CMD.", Recommendation = "Use DisableCMD = 2.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 2 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            Verification = "DisableCMD = 2 means scripts are also blocked.", ValueMap = "2 = Yes.",
            CliTokens = "Value 2 answers 'Yes' to the script-processing option.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Same policy dialog → 'Disable…script processing also?' = Yes",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Prevent access to the command prompt (policy option: Disable the command prompt script processing also? = Yes)",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc → the command prompt policy dialog", GoTo = "User Configuration > Administrative Templates > System > 'Prevent access to the command prompt' (dialog) > 'Disable the command prompt script processing also?' > Yes",
            GraphicalSteps = "1) Open 'Prevent access to the command prompt'. 2) Set the inner option 'Disable the command prompt script processing also?' = Yes.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 1",
            IgnoreConsequence = ".bat/.cmd scripts still run.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD",
            AlternativeToRegistry = "Prefer the policy dialog option." },
        new SubCheck { Id = "CMD-001.3", Title = "Don't run specified Windows applications (optional)", Expected = "Enabled — add cmd.exe / powershell.exe for non-admins",
            WhatItDoes = "Second layer denying specific executables for non-admin users.", Recommendation = "Add cmd.exe (and powershell.exe) to DisallowRun.",
            CheckCurrentCli = "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select DisallowRun",
            CliCommand = "New-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name DisallowRun -Value 1; New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun' -Name '1' -Value 'cmd.exe' -Force | Out-Null",
            VerifyCli = "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select DisallowRun",
            Verification = "DisallowRun = 1 and cmd.exe listed.", ValueMap = "1 = Enabled.",
            CliTokens = "DisallowRun: list-based executable deny for the user.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "User Config → System → Don't run specified Windows applications",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Don't run specified Windows applications",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc (root)", GoTo = "User Configuration > Administrative Templates > System > 'Don't run specified Windows applications' > Enabled > Add cmd.exe",
            GraphicalSteps = "1) 'Don't run specified Windows applications' = Enabled. 2) Show… add cmd.exe (and powershell.exe for non-admins).",
            UndoCli = "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name DisallowRun -ErrorAction SilentlyContinue",
            IgnoreConsequence = "No second-layer executable block.", HasRegistryPath = true,
            RegistryPath = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
            AlternativeToRegistry = "Prefer gpedit.msc → User Configuration → System." }
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

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Disabled", "Block cmd.exe and batch scripts for standard users to reduce attack surface.",
            errorMessage: errorMessage,
            description: "Blocks standard users from running cmd.exe and batch scripts.",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 2.9", riskScore: 50, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }
}