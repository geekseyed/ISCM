using System.Management;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class AdminAccountCountCheck : IHardeningCheck, IMultiPathCheck
{
    public string CheckId => "ADM-001";
    public string Name => "Admin Account Count";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = string.Empty;
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            string machineName = Environment.MachineName;
            string query = $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"";
            using var searcher = new ManagementObjectSearcher(query);
            int adminCount = searcher.Get().Count;
            currentValue = $"{adminCount} Admins";
            status = adminCount <= 2 ? CheckStatus.Pass : CheckStatus.Fail;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "<= 2 Admins",
            recommendation: "Limit local administrator group to essential members only.",
            errorMessage: errorMessage,
            description: "Limiting local administrators reduces the attack surface for privilege escalation. Excessive admin accounts increase the risk of credential theft.",
            registryPath: string.Empty,
            cisReference: "CIS 2.3.1.5",
            riskScore: 20,
            sourceType: "WMI (Win32_GroupUser)",
            sourceCommand: "net localgroup Administrators",
            fixTools: new List<string> { "powershell.exe", "compmgmt.msc" }
        ));
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: WMI Win32_GroupUser
        try
        {
            string machineName = Environment.MachineName;
            string query = $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"";
            using var searcher = new ManagementObjectSearcher(query);
            int count = searcher.Get().Count;
            var passed = count <= 2;
            results.Add(new TestResult("Primary", "WMI (Win32_GroupUser)", passed, $"Admin count = {count}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "WMI (Win32_GroupUser)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: net localgroup Administrators
        try
        {
            var psi = new ProcessStartInfo("net", "localgroup Administrators")
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
                var lines = output.Split('\n').Where(l => l.Contains("Administrator") && !l.Contains("Comment") && !l.Contains("Alias name")).ToList();
                var count = lines.Count;
                var passed = count <= 2;
                results.Add(new TestResult("Cross-check", "net localgroup", passed, $"Admin count = {count}"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "net localgroup", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: PowerShell Get-LocalGroupMember
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count\"")
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
                if (!string.IsNullOrWhiteSpace(output) && int.TryParse(output.Trim(), out int count))
                {
                    var passed = count <= 2;
                    results.Add(new TestResult("Verification", "PowerShell (Get-LocalGroupMember)", passed, $"Admin count = {count}"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "PowerShell (Get-LocalGroupMember)", false, "Could not query Administrators group"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "PowerShell (Get-LocalGroupMember)", false, $"Error: {ex.Message}"));
        }
        return results;
    }
}