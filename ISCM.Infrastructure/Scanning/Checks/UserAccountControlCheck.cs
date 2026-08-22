using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class UacCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    public string CheckId => "UAC-001";
    public string Name => "User Account Control (UAC)";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "UAC-001.1", Title = "User Account Control: Run all administrators in Admin Approval Mode",
            Expected = "Enabled",
            WhatItDoes = "Forces elevation through UAC instead of silent administrator execution.",
            Recommendation = "Set EnableLUA = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA",
            Verification = "EnableLUA = 1.",
            ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name EnableLUA: master UAC switch.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Run all administrators in Admin Approval Mode",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies > Security Options",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode > Enabled",
            GraphicalSteps = "1) Run secpol.msc.\n2) Navigate to Security Settings > Local Policies > Security Options.\n3) Double-click 'User Account Control: Run all administrators in Admin Approval Mode'.\n4) Set to Enabled.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0",
            IgnoreConsequence = "Administrators run fully elevated; silent privilege abuse possible.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options." },
        new SubCheck { Id = "UAC-001.2", Title = "User Account Control: Behavior of the elevation prompt for administrators",
            Expected = "Prompt for consent on the secure desktop",
            WhatItDoes = "Moves elevation prompts to the secure desktop.",
            Recommendation = "Set ConsentPromptBehaviorAdmin = 2.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin",
            Verification = "ConsentPromptBehaviorAdmin = 2.",
            ValueMap = "0 = Elevate without prompting, 2 = Prompt for consent on secure desktop.",
            CliTokens = "-Name ConsentPromptBehaviorAdmin: admin elevation prompt behavior.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Behavior of the elevation prompt (admin)",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Behavior of the elevation prompt for administrators",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies > Security Options",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Behavior of the elevation prompt for administrators > Prompt for consent on the secure desktop",
            GraphicalSteps = "1) Same Security Options node.\n2) Double-click 'User Account Control: Behavior of the elevation prompt for administrators'.\n3) Select 'Prompt for consent on the secure desktop'.\n4) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 0",
            IgnoreConsequence = "Elevation may occur without a secure prompt.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options." },
        new SubCheck { Id = "UAC-001.3", Title = "User Account Control: Detect application installations and prompt for elevation",
            Expected = "Enabled",
            WhatItDoes = "Detects installer behavior that requires elevation.",
            Recommendation = "Set EnableInstallerDetection = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection",
            Verification = "EnableInstallerDetection = 1.",
            ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name EnableInstallerDetection: installer detection switch.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Detect application installations",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Detect application installations and prompt for elevation",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies > Security Options",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Detect application installations and prompt for elevation > Enabled",
            GraphicalSteps = "1) Same Security Options node.\n2) Double-click 'User Account Control: Detect application installations and prompt for elevation'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection -Value 0",
            IgnoreConsequence = "Silent installer elevation goes unnoticed.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            var v = key?.GetValue("EnableLUA");
            if (v != null && v.ToString() == "1") { currentValue = "UAC Enabled"; status = CheckStatus.Pass; }
            else { currentValue = "UAC Disabled"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Enabled",
            "Enable UAC to require elevation consent on the secure desktop.",
            errorMessage: errorMessage,
            description: "User Account Control prevents silent administrator elevation and detects installer behavior.",
            registryPath: $@"HKLM\{RegPath}\EnableLUA",
            cisReference: "CIS 2.3.10.2",
            riskScore: 70,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v EnableLUA",
            fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry برای EnableLUA
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            if (key != null)
            {
                var v = key.GetValue("EnableLUA");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Primary", "Registry (EnableLUA)", passed, $"EnableLUA = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (EnableLUA)", false, "EnableLUA value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (EnableLUA)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (EnableLUA)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Registry برای ConsentPromptBehaviorAdmin
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            if (key != null)
            {
                var v = key.GetValue("ConsentPromptBehaviorAdmin");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 2;
                    var desc = val switch
                    {
                        0 => "Elevate without prompting",
                        1 => "Prompt for credentials on secure desktop",
                        2 => "Prompt for consent on secure desktop",
                        3 => "Prompt for credentials",
                        4 => "Prompt for consent",
                        5 => "Prompt for consent for non-Windows binaries",
                        _ => $"Unknown ({val})"
                    };
                    results.Add(new TestResult("Cross-check", "Registry (ConsentPromptBehaviorAdmin)", passed, $"Value = {val} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Registry (ConsentPromptBehaviorAdmin)", false, "Value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry (ConsentPromptBehaviorAdmin)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry (ConsentPromptBehaviorAdmin)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: PowerShell برای EnableInstallerDetection
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableInstallerDetection' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableInstallerDetection\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (!string.IsNullOrWhiteSpace(output) && int.TryParse(output.Trim(), out int val))
            {
                var passed = val == 1;
                results.Add(new TestResult("Verification", "PowerShell (EnableInstallerDetection)", passed, $"EnableInstallerDetection = {val}"));
            }
            else
            {
                results.Add(new TestResult("Verification", "PowerShell (EnableInstallerDetection)", false, "EnableInstallerDetection not configured"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "PowerShell (EnableInstallerDetection)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}