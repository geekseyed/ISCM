using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AccountLockoutCheck : IHardeningCheck, IMultiPathCheck
{
    public string CheckId => "LCK-001";
    public string Name => "Account Lockout Policy";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "LCK-001.1", Title = "Account lockout threshold", Expected = "5 invalid logon attempts",
            WhatItDoes = "Number of failed logons before the account is locked.", Recommendation = "Set threshold to 5.",
            CheckCurrentCli = "net accounts", CliCommand = "net accounts /lockoutthreshold:5",
            VerifyCli = "net accounts", Verification = "'Lockout threshold' shows 5.",
            ValueMap = "5 = lock after 5 fails; 0 = never lock.", CliTokens = "/lockoutthreshold: failed-logon limit.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Threshold",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout threshold",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout threshold > 5",
            GraphicalSteps = "1) secpol.msc → Account Policies → Account Lockout Policy. 2) Double-click 'Account lockout threshold'. 3) Set 5.",
            UndoCli = "net accounts /lockoutthreshold:0", IgnoreConsequence = "Brute-force attempts never lock the account.", HasRegistryPath = false },
        new SubCheck { Id = "LCK-001.2", Title = "Account lockout duration", Expected = "15 minutes",
            WhatItDoes = "How long the account stays locked after threshold.", Recommendation = "Set 15.",
            CheckCurrentCli = "net accounts", CliCommand = "net accounts /lockoutduration:15",
            VerifyCli = "net accounts", Verification = "'Lockout duration' shows 15.",
            ValueMap = "minutes.", CliTokens = "/lockoutduration: lock hold time.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Duration",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout duration",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy",
            YouAreHere = "secpol.msc → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout duration > 15",
            GraphicalSteps = "1) Account Lockout Policy. 2) 'Account lockout duration' = 15.",
            UndoCli = "net accounts /lockoutduration:0", IgnoreConsequence = "Locked accounts may stay locked too long/short.", HasRegistryPath = false },
        new SubCheck { Id = "LCK-001.3", Title = "Reset account lockout counter after", Expected = "15 minutes",
            WhatItDoes = "Time before the failed-attempt counter resets to zero.", Recommendation = "Set 15.",
            CheckCurrentCli = "net accounts", CliCommand = "net accounts /lockoutwindow:15",
            VerifyCli = "net accounts", Verification = "'Lockout observation window' shows 15.",
            ValueMap = "minutes.", CliTokens = "/lockoutwindow: counter reset window.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Reset counter",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Reset account lockout counter after",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy",
            YouAreHere = "secpol.msc → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Reset account lockout counter after > 15",
            GraphicalSteps = "1) Account Lockout Policy. 2) 'Reset account lockout counter after' = 15.",
            UndoCli = "net accounts /lockoutwindow:0", IgnoreConsequence = "Counter may reset too fast/slow.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            string output = Run("net", "accounts");
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var num = new string(line.Where(char.IsDigit).ToArray());
                if (int.TryParse(num, out int t))
                {
                    currentValue = t == 0 ? "Never" : t.ToString();
                    status = t >= 5 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Never";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Not available";
                status = CheckStatus.Unknown; // اصلاح شد: Warning به Unknown تغییر کرد
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "5", "Lock accounts after repeated failed logons to mitigate brute-force attacks.",
            errorMessage: errorMessage,
            description: "Locks user accounts after repeated failed logon attempts.",
            registryPath: null, cisReference: "CIS 5.4", riskScore: 60, sourceType: "net accounts",
            sourceCommand: "net accounts", fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        try
        {
            string output = Run("net", "accounts");
            var thresholdLine = output.Split('\n').FirstOrDefault(l => l.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase));
            if (thresholdLine != null)
            {
                var num = new string(thresholdLine.Where(char.IsDigit).ToArray());
                if (int.TryParse(num, out int threshold))
                {
                    var passed = threshold >= 5 && threshold > 0;
                    results.Add(new TestResult("Primary", "net accounts", passed, $"Lockout threshold = {threshold}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "net accounts", false, "Could not parse threshold"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "net accounts", false, "Lockout threshold not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "net accounts", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        try
        {
            if (!Directory.Exists(@"C:\temp")) Directory.CreateDirectory(@"C:\temp");

            var psi = new ProcessStartInfo("secedit.exe", "/export /cfg \"C:\\temp\\lockout.inf\" /areas SECURITYPOLICY")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (File.Exists(@"C:\temp\lockout.inf"))
            {
                var content = await File.ReadAllTextAsync(@"C:\temp\lockout.inf");
                var lockoutLine = content.Split('\n').FirstOrDefault(l => l.Contains("LockoutBadCount", StringComparison.OrdinalIgnoreCase));
                if (lockoutLine != null)
                {
                    var parts = lockoutLine.Split('=');
                    if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int lockoutCount))
                    {
                        var passed = lockoutCount >= 5 && lockoutCount > 0;
                        results.Add(new TestResult("Cross-check", "secedit", passed, $"LockoutBadCount = {lockoutCount}"));
                    }
                    else
                    {
                        results.Add(new TestResult("Cross-check", "secedit", false, "Could not parse LockoutBadCount"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "secedit", false, "LockoutBadCount not found in export"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "secedit", false, "secedit export failed"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "secedit", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-Command \"$output = net accounts; $threshold = ($output | Select-String 'Lockout threshold').ToString().Split(':')[-1].Trim(); $duration = ($output | Select-String 'Lockout duration').ToString().Split(':')[-1].Trim(); $window = ($output | Select-String 'Lockout observation').ToString().Split(':')[-1].Trim(); Write-Output \\\"T=$threshold|D=$duration|W=$window\\\"\"")
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
                    var parts = output.Trim().Split('|');
                    if (parts.Length >= 3)
                    {
                        var tVal = parts[0].Replace("T=", "").Trim();
                        var dVal = parts[1].Replace("D=", "").Trim();
                        var wVal = parts[2].Replace("W=", "").Trim();

                        var tNum = new string(tVal.Where(char.IsDigit).ToArray());
                        var dNum = new string(dVal.Where(char.IsDigit).ToArray());
                        var wNum = new string(wVal.Where(char.IsDigit).ToArray());

                        if (int.TryParse(tNum, out int t) && int.TryParse(dNum, out int d) && int.TryParse(wNum, out int w))
                        {
                            var passed = t >= 5 && t > 0 && d >= 15 && w >= 15;
                            results.Add(new TestResult("Verification", "PowerShell (lockout full verification)", passed, $"threshold={t}, duration={d}min, window={w}min"));
                        }
                        else
                        {
                            results.Add(new TestResult("Verification", "PowerShell (lockout full verification)", false, $"Raw output: {output.Trim()}"));
                        }
                    }
                    else
                    {
                        results.Add(new TestResult("Verification", "PowerShell (lockout full verification)", false, $"Could not parse output: {output.Trim()}"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Verification", "PowerShell (lockout full verification)", false, "Empty output from PowerShell"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "PowerShell (lockout full verification)", false, $"Error: {ex.Message}"));
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