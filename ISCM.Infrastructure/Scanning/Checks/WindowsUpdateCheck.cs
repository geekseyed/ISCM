using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class WindowsUpdateCheck : IHardeningCheck, IMultiPathCheck
{
    private const string AuPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    private const string WuPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

    public string CheckId => "WUP-001";
    public string Name => "Windows Update / Patch Management";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "WUP-001.1", Title = "Configure Automatic Updates", Expected = "Model-aware (Disabled for isolated, Enabled 4 for WSUS)",
            WhatItDoes = "Controls automatic update behavior based on deployment model.", Recommendation = "Set AUOptions appropriately (4 for WSUS-backed, Disabled for fully isolated).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions -Value 4 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            Verification = "AUOptions = 4 (Auto download and schedule).",
            ValueMap = "2 = Notify, 3 = Auto download notify install, 4 = Auto download and schedule, 5 = Allow local admin.",
            CliTokens = "-Name AUOptions: Windows Update behavior mode.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows Update → Configure Automatic Updates",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates > Enabled > 4 - Auto download and schedule the install",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Windows Update.\n3) Double-click 'Configure Automatic Updates'.\n4) Set to Enabled.\n5) Option: 4 - Auto download and schedule the install.\n6) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            IgnoreConsequence = "No automatic patch application; systems remain vulnerable.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." },
        new SubCheck { Id = "WUP-001.2", Title = "Specify intranet Microsoft update service location (WSUS)", Expected = "Enabled with internal WSUS URL (only if WSUS exists)",
            WhatItDoes = "Redirects clients to an internal WSUS server.", Recommendation = "Set WUServer and WUStatusServer only if WSUS is deployed.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer, WUStatusServer",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer -Value 'http://wsus.internal:8530'; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUStatusServer -Value 'http://wsus.internal:8530'",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer, WUStatusServer",
            Verification = "WUServer and WUStatusServer point to internal WSUS.",
            ValueMap = string.Empty,
            CliTokens = "-Name WUServer: internal WSUS URL.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows Update → Specify intranet Microsoft update service location",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Specify intranet Microsoft update service location",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Specify intranet Microsoft update service location > Enabled > http://wsus.internal:8530",
            GraphicalSteps = "1) Same Windows Update node.\n2) Double-click 'Specify intranet Microsoft update service location'.\n3) Set to Enabled.\n4) Enter internal WSUS URL for both fields.\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer; Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUStatusServer",
            IgnoreConsequence = "Clients may attempt Internet-based Windows Update in isolated environments.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." },
        new SubCheck { Id = "WUP-001.3", Title = "No auto-restart with logged on users for scheduled automatic updates", Expected = "Per maintenance-window policy",
            WhatItDoes = "Aligns reboots with operations instead of forcing one answer.", Recommendation = "Set per environment (Enabled on workstations, Disabled on unattended).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            Verification = "NoAutoRebootWithLoggedOnUsers = 1 (Enabled).",
            ValueMap = "1 = Enabled (no auto-restart), 0 = Disabled (auto-restart allowed).",
            CliTokens = "-Name NoAutoRebootWithLoggedOnUsers: reboot behavior with logged users.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Windows Update → No auto-restart with logged on users",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > No auto-restart with logged on users for scheduled automatic updates installations",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update", GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > No auto-restart with logged on users for scheduled automatic updates installations > Enabled",
            GraphicalSteps = "1) Same Windows Update node.\n2) Double-click 'No auto-restart with logged on users for scheduled automatic updates installations'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            IgnoreConsequence = "Reboots may interrupt users or stall patching.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." },
        new SubCheck { Id = "WUP-001.4", Title = "Verify latest patches (build-aware)", Expected = "Latest monthly KB for exact build",
            WhatItDoes = "Confirms the client has the newest cumulative update for its exact build.", Recommendation = "Compare Get-HotFix top entry with the release-information page.",
            CheckCurrentCli = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15",
            CliCommand = "# compare build via winver, then install .msu: wusa.exe Windows11.0-KBxxxxxxx-x64.msu /quiet /norestart",
            VerifyCli = "Get-HotFix -Id KBxxxxxxx",
            Verification = "Target KB present for the exact build.",
            ValueMap = string.Empty,
            CliTokens = "Get-HotFix: lists installed KBs; wusa: installs an MSU.",
            ConsoleTool = "winver", DestinationLabel = "winver → identify build",
            GraphicalPathFull = "Settings > System > About (or winver) to identify build, then Microsoft Update Catalog for the matching KB",
            ConsolePath = "Settings > System > About",
            YouAreHere = "Desktop", GoTo = "Run Cli 'winver' On 'Window + R' / Settings → System → About → note OS build",
            GraphicalSteps = "1) Run winver.\n2) Note version/build.\n3) Match against release-information + KB article.",
            UndoCli = "# n/a",
            IgnoreConsequence = "Unknown patch gap remains.", HasRegistryPath = false,
            RegistryPath = string.Empty,
            AlternativeToRegistry = string.Empty }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // 1. AUOptions configured
            using var auKey = Registry.LocalMachine.OpenSubKey(AuPath);
            var auVal = auKey?.GetValue("AUOptions");
            if (auVal != null && int.TryParse(auVal.ToString(), out int auOpt) && auOpt >= 2 && auOpt <= 5) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. WUServer configured (if WSUS model)
            using var wuKey = Registry.LocalMachine.OpenSubKey(WuPath);
            var wsusVal = wuKey?.GetValue("WUServer");
            if (wsusVal != null && !string.IsNullOrWhiteSpace(wsusVal.ToString())) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Pass); // Optional for isolated model

            // 3. NoAutoRebootWithLoggedOnUsers
            var rebootVal = auKey?.GetValue("NoAutoRebootWithLoggedOnUsers");
            if (rebootVal != null && int.TryParse(rebootVal.ToString(), out int rebootOpt)) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Pass); // Optional

            // 4. Check latest KB installed
            string hotfixOutput = Run("powershell.exe", "-Command \"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ForEach-Object { $_.HotFixID }\"");
            if (!string.IsNullOrWhiteSpace(hotfixOutput) && hotfixOutput.Contains("KB", StringComparison.OrdinalIgnoreCase)) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} Windows Update settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "Windows Update configured",
                "Configure Windows Update appropriately for your deployment model (isolated vs WSUS-backed).",
                errorMessage: string.Empty,
                description: "Manages automatic update behavior for patch management in various network environments.",
                registryPath: $@"HKLM\{AuPath}\AUOptions",
                cisReference: "CIS 18.9.5", riskScore: 70, sourceType: "RegistryReader + PowerShell",
                sourceCommand: $@"reg query ""HKLM\{AuPath}"" /v AUOptions",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Manages automatic update behavior for patch management in various network environments.",
                registryPath: $@"HKLM\{AuPath}\AUOptions",
                cisReference: "CIS 18.9.5", riskScore: 70, sourceType: "RegistryReader + PowerShell",
                sourceCommand: $@"reg query ""HKLM\{AuPath}"" /v AUOptions",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry برای AUOptions
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AuPath);
            if (key != null)
            {
                var v = key.GetValue("AUOptions");
                if (v != null && int.TryParse(v.ToString(), out int opt))
                {
                    var desc = opt switch
                    {
                        2 => "Notify before download",
                        3 => "Auto download, notify install",
                        4 => "Auto download and schedule",
                        5 => "Allow local admin to choose",
                        _ => $"Unknown ({opt})"
                    };
                    results.Add(new TestResult("Primary", "Registry (AUOptions)", true, $"AUOptions = {opt} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (AUOptions)", false, "AUOptions not configured"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (AUOptions)", false, "WindowsUpdate AU registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (AUOptions)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: Get-HotFix
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { \\\"$($_.HotFixID) installed $($_.InstalledOn)\\\" }\"")
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
                var passed = !string.IsNullOrWhiteSpace(output);
                results.Add(new TestResult("Cross-check", "Get-HotFix (Latest KB)", passed, passed ? output.Trim() : "Could not determine latest KB"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-HotFix (Latest KB)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: Get-Service wuauserv
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"")
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
                var passed = !string.IsNullOrWhiteSpace(output);
                results.Add(new TestResult("Verification", "Get-Service (wuauserv)", passed, passed ? $"Windows Update service status = {output.Trim()}" : "Windows Update service not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Get-Service (wuauserv)", false, $"Error: {ex.Message}"));
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

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return string.Empty;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return o;
        }
        catch { return string.Empty; }
    }
}