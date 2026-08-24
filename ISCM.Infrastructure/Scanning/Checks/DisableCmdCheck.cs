using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class DisableCmdCheck : IHardeningCheck, IMultiPathCheck
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
            WhatItDoes = "Disables cmd.exe for targeted (standard) users.", Recommendation = "DisableCMD = 1 or 2.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name DisableCMD -Value 2 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' | Select DisableCMD",
            Verification = "DisableCMD = 1 or 2.",
            ValueMap = "1 = disable CMD only, 2 = disable CMD + scripts.",
            CliTokens = "-Name DisableCMD: blocks cmd.exe; value 2 also blocks script processing.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "User Config → System → Prevent access to the command prompt",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Prevent access to the command prompt",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc (root)", GoTo = "User Configuration > Administrative Templates > System > Prevent access to the command prompt > Enabled",
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
            Verification = "DisableCMD = 2 means scripts are also blocked.",
            ValueMap = "2 = Yes.",
            CliTokens = "Value 2 answers 'Yes' to the script-processing option.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Same policy dialog → 'Disable…script processing also?' = Yes",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Prevent access to the command prompt (policy option: Disable the command prompt script processing also? = Yes)",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc → the command prompt policy dialog", GoTo = "Inside the policy → 'Disable the command prompt script processing also?' = Yes",
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
            Verification = "DisallowRun = 1 and cmd.exe listed.",
            ValueMap = "1 = Enabled.",
            CliTokens = "DisallowRun: list-based executable deny for the user.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "User Config → System → Don't run specified Windows applications",
            GraphicalPathFull = "User Configuration > Administrative Templates > System > Don't run specified Windows applications",
            ConsolePath = "User Configuration > Administrative Templates > System",
            YouAreHere = "gpedit.msc (root)", GoTo = "User Configuration > Administrative Templates > System > Don't run specified Windows applications > Enabled > add cmd.exe",
            GraphicalSteps = "1) 'Don't run specified Windows applications' = Enabled. 2) Show… add cmd.exe (and powershell.exe for non-admins).",
            UndoCli = "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name DisallowRun -ErrorAction SilentlyContinue",
            IgnoreConsequence = "No second-layer executable block.", HasRegistryPath = true,
            RegistryPath = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
            AlternativeToRegistry = "Prefer gpedit.msc → User Configuration → System." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // 1. DisableCMD = 1 or 2
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            var v = key?.GetValue(ValueName);
            if (v != null && (v.ToString() == "1" || v.ToString() == "2")) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. Check if value is 2 (scripts also blocked)
            if (v != null && v.ToString() == "2") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 3. DisallowRun for cmd.exe
            using var explorerKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
            var disallowRunVal = explorerKey?.GetValue("DisallowRun");
            if (disallowRunVal != null && disallowRunVal.ToString() == "1")
            {
                using var disallowRunKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun");
                if (disallowRunKey != null)
                {
                    var values = disallowRunKey.GetValueNames();
                    var hasCmd = values.Any(name => disallowRunKey.GetValue(name)?.ToString()?.Contains("cmd.exe") == true);
                    statuses.Add(hasCmd ? CheckStatus.Pass : CheckStatus.Fail);
                }
                else
                {
                    statuses.Add(CheckStatus.Fail);
                }
            }
            else
            {
                statuses.Add(CheckStatus.Fail);
            }

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} CMD/Script settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "CMD & Script execution disabled",
                "Block cmd.exe and batch scripts for standard users to reduce attack surface.",
                errorMessage: string.Empty,
                description: "Blocks standard users from running cmd.exe and batch scripts.",
                registryPath: $@"HKLM\{RegPath}\{ValueName}",
                cisReference: "CIS 2.9", riskScore: 50, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Blocks standard users from running cmd.exe and batch scripts.",
                registryPath: $@"HKLM\{RegPath}\{ValueName}",
                cisReference: "CIS 2.9", riskScore: 50, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry HKCU DisallowRun
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
            if (key != null)
            {
                var v = key.GetValue("DisallowRun");
                if (v != null && v.ToString() == "1")
                {
                    using var subKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun");
                    if (subKey != null)
                    {
                        var values = subKey.GetValueNames();
                        var hasCmd = values.Any(name => subKey.GetValue(name)?.ToString()?.Contains("cmd.exe") == true);
                        results.Add(new TestResult("Primary", "Registry HKCU DisallowRun", hasCmd, hasCmd ? "cmd.exe in DisallowRun list" : "DisallowRun=1 but cmd.exe not found"));
                    }
                    else
                    {
                        results.Add(new TestResult("Primary", "Registry HKCU DisallowRun", false, "DisallowRun=1 but subkey not found"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry HKCU DisallowRun", false, $"DisallowRun = {v}"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry HKCU DisallowRun", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry HKCU DisallowRun", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: Registry HKLM DisableCMD
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null)
                {
                    var val = int.Parse(v.ToString()!);
                    var passed = val == 1 || val == 2;
                    results.Add(new TestResult("Cross-check", "Registry HKLM DisableCMD", passed, $"DisableCMD = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Registry HKLM DisableCMD", false, "DisableCMD value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry HKLM DisableCMD", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry HKLM DisableCMD", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: PowerShell policy check
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name 'DisableCMD' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableCMD\"")
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
                    var val = int.Parse(output.Trim());
                    var passed = val == 1 || val == 2;
                    results.Add(new TestResult("Verification", "PowerShell Get-ItemProperty", passed, $"DisableCMD = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "PowerShell Get-ItemProperty", false, "Value not found"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "PowerShell Get-ItemProperty", false, $"Error: {ex.Message}"));
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