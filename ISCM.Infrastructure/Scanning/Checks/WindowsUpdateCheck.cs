using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

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
        new SubCheck { Id = "WUP-001.1", Title = "Configure Automatic Updates",
            Expected = "Model-aware (Disabled for isolated, Enabled 4 for WSUS)",
            WhatItDoes = "Controls automatic update behavior based on deployment model.",
            Recommendation = "Set AUOptions appropriately (4 for WSUS-backed, Disabled for fully isolated).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions -Value 4 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            Verification = "AUOptions = 4 (Auto download and schedule).",
            ValueMap = "2 = Notify, 3 = Auto download notify install, 4 = Auto download and schedule, 5 = Allow local admin.",
            CliTokens = "-Name AUOptions: Windows Update behavior mode.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → Configure Automatic Updates",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates > Enabled > 4 - Auto download and schedule the install",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Windows Update.\n3) Double-click 'Configure Automatic Updates'.\n4) Set to Enabled.\n5) Option: 4 - Auto download and schedule the install.\n6) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions",
            IgnoreConsequence = "No automatic patch application; systems remain vulnerable.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." },
        new SubCheck { Id = "WUP-001.2", Title = "Specify intranet Microsoft update service location (WSUS)",
            Expected = "Enabled with internal WSUS URL (only if WSUS exists)",
            WhatItDoes = "Redirects clients to an internal WSUS server.",
            Recommendation = "Set WUServer and WUStatusServer only if WSUS is deployed.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer, WUStatusServer",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer -Value 'http://wsus.internal:8530'; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUStatusServer -Value 'http://wsus.internal:8530'",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer, WUStatusServer",
            Verification = "WUServer and WUStatusServer point to internal WSUS.",
            ValueMap = "",
            CliTokens = "-Name WUServer: internal WSUS URL.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → Specify intranet Microsoft update service location",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Specify intranet Microsoft update service location",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Specify intranet Microsoft update service location > Enabled > http://wsus.internal:8530",
            GraphicalSteps = "1) Same Windows Update node.\n2) Double-click 'Specify intranet Microsoft update service location'.\n3) Set to Enabled.\n4) Enter internal WSUS URL for both fields.\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer; Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUStatusServer",
            IgnoreConsequence = "Clients may attempt Internet-based Windows Update in isolated environments.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." },
        new SubCheck { Id = "WUP-001.3", Title = "No auto-restart with logged on users for scheduled automatic updates",
            Expected = "Per maintenance-window policy",
            WhatItDoes = "Aligns reboots with operations instead of forcing one answer.",
            Recommendation = "Set per environment (Enabled on workstations, Disabled on unattended).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            Verification = "NoAutoRebootWithLoggedOnUsers = 1 (Enabled).",
            ValueMap = "1 = Enabled (no auto-restart), 0 = Disabled (auto-restart allowed).",
            CliTokens = "-Name NoAutoRebootWithLoggedOnUsers: reboot behavior with logged users.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → No auto-restart with logged on users",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > No auto-restart with logged on users for scheduled automatic updates installations",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Windows Update",
            YouAreHere = "gpedit.msc > Windows Components > Windows Update",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Windows Update > No auto-restart with logged on users for scheduled automatic updates installations > Enabled",
            GraphicalSteps = "1) Same Windows Update node.\n2) Double-click 'No auto-restart with logged on users for scheduled automatic updates installations'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers",
            IgnoreConsequence = "Reboots may interrupt users or stall patching.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers",
            AlternativeToRegistry = "Prefer gpedit.msc > Windows Update." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AuPath);
            var v = key?.GetValue("AUOptions");
            if (v != null)
            {
                currentValue = $"AUOptions = {v}";
                status = CheckStatus.Pass; // Any configured value is acceptable; model-aware
            }
            else
            {
                currentValue = "Not configured";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Configured (model-aware)",
            "Configure Windows Update appropriately for your deployment model (isolated vs WSUS-backed).",
            errorMessage: errorMessage,
            description: "Manages automatic update behavior for patch management in various network environments.",
            registryPath: $@"HKLM\{AuPath}\AUOptions",
            cisReference: "CIS 18.9.5",
            riskScore: 70,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{AuPath}"" /v AUOptions",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
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
                    results.Add(new TestResult("Primary", "Registry (AUOptions)", false, "AUOptions not configured (uses default Windows Update behavior)"));
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

        // Test 2: Get-HotFix برای بررسی آخرین KB نصب‌شده
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { \\\"$($_.HotFixID) installed $($_.InstalledOn)\\\" }\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = !string.IsNullOrWhiteSpace(output);
            var details = passed ? output.Trim() : "Could not determine latest KB";
            results.Add(new TestResult("Cross-check", "Get-HotFix (Latest KB)", passed, details));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-HotFix (Latest KB)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: Get-Service برای wuauserv (Windows Update service)
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = !string.IsNullOrWhiteSpace(output);
            var details = passed ? $"Windows Update service status = {output.Trim()}" : "Windows Update service not found";
            results.Add(new TestResult("Verification", "Get-Service (wuauserv)", passed, details));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Get-Service (wuauserv)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}