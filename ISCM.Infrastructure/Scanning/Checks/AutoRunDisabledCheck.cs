using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AutoRunDisabledCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegPathHKLM = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string RegPathHKCU = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string ValueName = "NoDriveTypeAutoRun";

    public string CheckId => "ARD-001";
    public string Name => "Disable Autorun/Autoplay";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "ARD-001.1", Title = "Turn off AutoPlay", Expected = "Enabled — All drives",
            WhatItDoes = "Disables AutoPlay on every drive type including USB.", Recommendation = "NoDriveTypeAutoRun = 255.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoDriveTypeAutoRun",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoDriveTypeAutoRun",
            Verification = "NoDriveTypeAutoRun = 255.",
            ValueMap = "255 = all drives off.",
            CliTokens = "NoDriveTypeAutoRun 255: disables AutoPlay for all drive types.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "AutoPlay Policies → Turn off AutoPlay",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies",
            YouAreHere = "gpedit.msc (root)",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay > Enabled > All drives",
            GraphicalSteps = "1) gpedit.msc → Windows Components → AutoPlay Policies. 2) Turn off AutoPlay. 3) Enabled, option All drives.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 0",
            IgnoreConsequence = "USB malware can auto-execute.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies." },
        new SubCheck { Id = "ARD-001.2", Title = "Set the default behavior for AutoRun", Expected = "Enabled — Do not execute any autorun commands",
            WhatItDoes = "Prevents autorun.inf auto-execution.", Recommendation = "NoAutorun = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoAutorun",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutorun -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoAutorun",
            Verification = "NoAutorun = 1.",
            ValueMap = "1 = do not execute autorun.",
            CliTokens = "NoAutorun 1: blocks autorun.inf commands.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "AutoPlay Policies → Default behavior for AutoRun",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Set the default behavior for AutoRun",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies",
            YouAreHere = "gpedit.msc (root)",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Set the default behavior for AutoRun > Enabled > Do not execute any autorun commands",
            GraphicalSteps = "1) AutoPlay Policies. 2) 'Set the default behavior for AutoRun'. 3) Enabled — Do not execute any autorun commands.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutorun -Value 0",
            IgnoreConsequence = "autorun.inf still runs.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies." },
        new SubCheck { Id = "ARD-001.3", Title = "Disallow Autoplay for non-volume devices", Expected = "Enabled",
            WhatItDoes = "Blocks AutoPlay for MTP phones/cameras.", Recommendation = "NoAutoplayfornonVolume = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoAutoplayfornonVolume",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | Select NoAutoplayfornonVolume",
            Verification = "NoAutoplayfornonVolume = 1.",
            ValueMap = "1 = Enabled.",
            CliTokens = "NoAutoplayfornonVolume: blocks AutoPlay on non-volume (MTP/PTP) devices.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "AutoPlay Policies → Disallow Autoplay for non-volume devices",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Disallow Autoplay for non-volume devices",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies",
            YouAreHere = "gpedit.msc (root)",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Disallow Autoplay for non-volume devices > Enabled",
            GraphicalSteps = "1) AutoPlay Policies. 2) 'Disallow Autoplay for non-volume devices'. 3) Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutoplayfornonVolume -Value 0",
            IgnoreConsequence = "MTP devices can trigger AutoPlay.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoplayfornonVolume",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPathHKLM);
            var v = key?.GetValue(ValueName);

            if (v != null && int.TryParse(v.ToString(), out int val) && val == 255)
            {
                currentValue = "AutoPlay Disabled (255)";
                status = CheckStatus.Pass;
            }
            else
            {
                currentValue = v?.ToString() ?? "Not configured";
                status = CheckStatus.Fail;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
            currentValue = $"Error: {ex.GetType().Name}";
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "255",
            "Disable AutoPlay/AutoRun to prevent USB malware auto-execution.",
            errorMessage: errorMessage,
            description: "Prevents automatic execution of code on USB drives, CDs, and other removable media.",
            registryPath: $@"HKLM\{RegPathHKLM}\{ValueName}",
            cisReference: "CIS 18.8.3.1",
            riskScore: 55,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPathHKLM}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry HKLM برای NoDriveTypeAutoRun
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPathHKLM);
            if (key != null)
            {
                var v = key.GetValue("NoDriveTypeAutoRun");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 255;
                    results.Add(new TestResult("Primary", "Registry HKLM (NoDriveTypeAutoRun)", passed, $"NoDriveTypeAutoRun = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry HKLM (NoDriveTypeAutoRun)", false, "NoDriveTypeAutoRun value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry HKLM (NoDriveTypeAutoRun)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry HKLM (NoDriveTypeAutoRun)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Registry HKCU برای NoDriveTypeAutoRun (user-level policy)
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegPathHKCU);
            if (key != null)
            {
                var v = key.GetValue("NoDriveTypeAutoRun");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 255;
                    results.Add(new TestResult("Cross-check", "Registry HKCU (NoDriveTypeAutoRun)", passed, $"NoDriveTypeAutoRun = {val}"));
                }
                else
                {
                    // HKCU policy not set = machine policy still applies
                    results.Add(new TestResult("Cross-check", "Registry HKCU (NoDriveTypeAutoRun)", true, "HKCU policy not set (machine policy applies)"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry HKCU (NoDriveTypeAutoRun)", true, "HKCU key not found (machine policy applies)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry HKCU (NoDriveTypeAutoRun)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: Registry HKLM برای NoAutoplayfornonVolume (MTP devices)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPathHKLM);
            if (key != null)
            {
                var v = key.GetValue("NoAutoplayfornonVolume");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Verification", "Registry (NoAutoplayfornonVolume)", passed, $"NoAutoplayfornonVolume = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "Registry (NoAutoplayfornonVolume)", false, "NoAutoplayfornonVolume value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (NoAutoplayfornonVolume)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (NoAutoplayfornonVolume)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}