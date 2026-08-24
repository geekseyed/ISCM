using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class AutoRunDisabledCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegPathHKLM = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string RegPathHKCU = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";

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
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay > Enabled > All drives",
            GraphicalSteps = "1) gpedit.msc → Windows Components → AutoPlay Policies. 2) Turn off AutoPlay. 3) Enabled, option All drives.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 0",
            IgnoreConsequence = "USB malware can auto-execute.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
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
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Set the default behavior for AutoRun > Enabled > Do not execute any autorun commands",
            GraphicalSteps = "1) AutoPlay Policies. 2) 'Set the default behavior for AutoRun'. 3) Enabled — Do not execute any autorun commands.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutorun -Value 0",
            IgnoreConsequence = "autorun.inf still runs.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun",
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
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Disallow Autoplay for non-volume devices > Enabled",
            GraphicalSteps = "1) AutoPlay Policies. 2) 'Disallow Autoplay for non-volume devices'. 3) Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutoplayfornonVolume -Value 0",
            IgnoreConsequence = "MTP devices can trigger AutoPlay.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoplayfornonVolume",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPathHKLM);

            // 1. NoDriveTypeAutoRun = 255
            var autoRunVal = key?.GetValue("NoDriveTypeAutoRun");
            if (autoRunVal != null && int.TryParse(autoRunVal.ToString(), out int autoRun) && autoRun == 255) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. NoAutorun = 1
            var noAutorunVal = key?.GetValue("NoAutorun");
            if (noAutorunVal != null && noAutorunVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 3. NoAutoplayfornonVolume = 1
            var nonVolumeVal = key?.GetValue("NoAutoplayfornonVolume");
            if (nonVolumeVal != null && nonVolumeVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} Autorun/Autoplay settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "Autorun/Autoplay disabled",
                "Disable AutoPlay/AutoRun to prevent USB malware auto-execution.",
                errorMessage: string.Empty,
                description: "Prevents automatic execution of code on USB drives, CDs, and other removable media.",
                registryPath: $@"HKLM\{RegPathHKLM}\NoDriveTypeAutoRun",
                cisReference: "CIS 18.8.3.1", riskScore: 55, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPathHKLM}"" /v NoDriveTypeAutoRun",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Prevents automatic execution of code on USB drives, CDs, and other removable media.",
                registryPath: $@"HKLM\{RegPathHKLM}\NoDriveTypeAutoRun",
                cisReference: "CIS 18.8.3.1", riskScore: 55, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPathHKLM}"" /v NoDriveTypeAutoRun",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
    }

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

        // Test 2: Registry HKCU برای NoDriveTypeAutoRun
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

        // Test 3: Registry HKLM برای NoAutoplayfornonVolume
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

    private static CheckStatus GetWorstStatus(IEnumerable<CheckStatus> statuses)
    {
        if (statuses.Any(s => s == CheckStatus.Fail)) return CheckStatus.Fail;
        if (statuses.Any(s => s == CheckStatus.Error)) return CheckStatus.Error;
        if (statuses.Any(s => s == CheckStatus.Unknown)) return CheckStatus.Unknown;
        return CheckStatus.Pass;
    }
}