using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class ProcessCreationAuditingCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string ValueName = "ProcessCreationIncludeCmdLine_Enabled";

    public string CheckId => "PRC-001";
    public string Name => "Process Creation Auditing";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "PRC-001.1", Title = "Audit Process Creation (Event 4688)", Expected = "Success",
            WhatItDoes = "Generates Event 4688 for every new process.", Recommendation = "Enable Success for Process Creation.",
            CheckCurrentCli = "auditpol /get /subcategory:\"Process Creation\"", CliCommand = "auditpol /set /subcategory:\"Process Creation\" /success:enable",
            VerifyCli = "auditpol /get /subcategory:\"Process Creation\"", Verification = "Success auditing enabled.",
            ValueMap = "", CliTokens = "/subcategory: the Detailed Tracking subcategory; /success:enable logs creations.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Detailed Tracking → Audit Process Creation",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking > Audit Process Creation",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking",
            YouAreHere = "secpol.msc → Advanced Audit Policy Configuration → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking > Audit Process Creation > Success",
            GraphicalSteps = "1) secpol.msc → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking. 2) Double-click 'Audit Process Creation'. 3) Check Success.",
            UndoCli = "auditpol /set /subcategory:\"Process Creation\" /success:disable", IgnoreConsequence = "No process-creation trail for forensics.", HasRegistryPath = false },
        new SubCheck { Id = "PRC-001.2", Title = "Include command line in process creation events", Expected = "Enabled",
            WhatItDoes = "Adds full command-line arguments to Event 4688.", Recommendation = "ProcessCreationIncludeCmdLine_Enabled = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' | Select ProcessCreationIncludeCmdLine_Enabled",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' | Select ProcessCreationIncludeCmdLine_Enabled",
            Verification = "ProcessCreationIncludeCmdLine_Enabled = 1.", ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name ProcessCreationIncludeCmdLine_Enabled: embeds command lines in 4688.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "System → Audit Process Creation → Include command line",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Audit Process Creation",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events > Enabled",
            GraphicalSteps = "1) gpedit.msc → Computer Configuration → Administrative Templates → System → Audit Process Creation. 2) 'Include command line in process creation events' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 0",
            IgnoreConsequence = "4688 events lack command-line detail.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled",
            AlternativeToRegistry = "Prefer gpedit.msc → System → Audit Process Creation." },
        new SubCheck { Id = "PRC-001.3", Title = "Audit: Force audit policy subcategory settings to override category settings", Expected = "Enabled",
            WhatItDoes = "Prevents basic audit policy from overwriting advanced subcategory settings.", Recommendation = "SCENoApplyLegacyAuditPolicy = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select SCENoApplyLegacyAuditPolicy",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select SCENoApplyLegacyAuditPolicy",
            Verification = "SCENoApplyLegacyAuditPolicy = 1.", ValueMap = "1 = subcategories override categories.",
            CliTokens = "-Name SCENoApplyLegacyAuditPolicy: forces advanced audit subcategories to win.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → Force audit subcategory override",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings > Enabled",
            GraphicalSteps = "1) secpol.msc → Local Policies → Security Options. 2) Double-click 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'. 3) Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 0",
            IgnoreConsequence = "Legacy audit policy may overwrite your subcategory settings.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy",
            AlternativeToRegistry = "Prefer secpol.msc → Security Options." }
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
            "Enabled", "Enable process-creation auditing with command-line capture for forensic visibility.",
            errorMessage: errorMessage,
            description: "Records every new process along with its full command line (Event 4688).",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 10.2", riskScore: 55, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc", "secpol.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry برای ProcessCreationIncludeCmdLine_Enabled
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null && v.ToString() == "1")
                {
                    results.Add(new TestResult("Primary", "Registry (ProcessCreationIncludeCmdLine_Enabled)", true, "Value = 1 (Enabled)"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (ProcessCreationIncludeCmdLine_Enabled)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (ProcessCreationIncludeCmdLine_Enabled)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (ProcessCreationIncludeCmdLine_Enabled)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: auditpol برای Process Creation
        try
        {
            string output = Run("auditpol", "/get /subcategory:\"Process Creation\"");
            var passed = output.Contains("Success", StringComparison.OrdinalIgnoreCase);
            var details = passed ? "Process Creation audit: Success enabled" : "Process Creation audit not enabled";
            results.Add(new TestResult("Cross-check", "auditpol (Process Creation)", passed, details));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "auditpol (Process Creation)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: Registry برای SCENoApplyLegacyAuditPolicy
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            if (key != null)
            {
                var v = key.GetValue("SCENoApplyLegacyAuditPolicy");
                if (v != null && v.ToString() == "1")
                {
                    results.Add(new TestResult("Verification", "Registry (SCENoApplyLegacyAuditPolicy)", true, "Value = 1 (subcategories override)"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "Registry (SCENoApplyLegacyAuditPolicy)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (SCENoApplyLegacyAuditPolicy)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (SCENoApplyLegacyAuditPolicy)", false, $"Error: {ex.Message}"));
        }

        return results;
    }

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return o;
        }
        catch { return ""; }
    }
}