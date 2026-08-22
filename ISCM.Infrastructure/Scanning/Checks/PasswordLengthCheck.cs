using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class PasswordLengthCheck : IHardeningCheck, IMultiPathCheck
{
    public string CheckId => "PWD-001";
    public string Name => "Password Policy";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "PWD-001.1", Title = "Enforce password history", Expected = "24 passwords remembered",
            WhatItDoes = "Prevents users from reusing recent passwords.",
            Recommendation = "Keep history at 24.",
            CheckCurrentCli = "net accounts",
            CliCommand = "# secpol.msc → Account Policies → Password Policy → Enforce password history = 24",
            VerifyCli = "net accounts", Verification = "secpol → Password Policy → 'Enforce password history' shows 24.",
            ValueMap = "", CliTokens = "",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Enforce password history",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Enforce password history",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Enforce password history > 24",
            GraphicalSteps = "1) Open secpol.msc. 2) Expand Account Policies. 3) Click Password Policy. 4) Right pane: double-click 'Enforce password history'. 5) Set 24.",
            UndoCli = "# set back to previous value", IgnoreConsequence = "Weak reuse of old passwords becomes possible.", HasRegistryPath = false },
        new SubCheck { Id = "PWD-001.2", Title = "Maximum password age", Expected = "60 days",
            WhatItDoes = "Forces periodic password changes.", Recommendation = "Set 60 days.",
            CheckCurrentCli = "net accounts", CliCommand = "# secpol.msc → Password Policy → Maximum password age = 60",
            VerifyCli = "net accounts", Verification = "'Maximum password age' shows 60.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Maximum password age",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Maximum password age",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Maximum password age > 60",
            GraphicalSteps = "1) secpol.msc → Account Policies → Password Policy. 2) Double-click 'Maximum password age'. 3) Set 60.",
            UndoCli = "# revert", IgnoreConsequence = "Stale passwords remain valid indefinitely.", HasRegistryPath = false },
        new SubCheck { Id = "PWD-001.3", Title = "Minimum password age", Expected = "1 day",
            WhatItDoes = "Stops rapid password cycling to bypass history.", Recommendation = "Set 1 day.",
            CheckCurrentCli = "net accounts", CliCommand = "# secpol.msc → Password Policy → Minimum password age = 1",
            VerifyCli = "net accounts", Verification = "'Minimum password age' shows 1.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Minimum password age",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password age",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password age > 1",
            GraphicalSteps = "1) secpol.msc → Account Policies → Password Policy. 2) Double-click 'Minimum password age'. 3) Set 1.",
            UndoCli = "# revert", IgnoreConsequence = "Users can cycle passwords instantly to defeat history.", HasRegistryPath = false },
        new SubCheck { Id = "PWD-001.4", Title = "Minimum password length", Expected = "14 characters",
            WhatItDoes = "Raises resistance to brute-force.", Recommendation = "Enforce 14.",
            CheckCurrentCli = "net accounts", CliCommand = "net accounts /minpwlen:14",
            VerifyCli = "net accounts", Verification = "'Minimum password length' shows 14.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Minimum password length",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length > 14",
            GraphicalSteps = "1) secpol.msc → Account Policies → Password Policy. 2) Double-click 'Minimum password length'. 3) Set 14.",
            UndoCli = "net accounts /minpwlen:0", IgnoreConsequence = "Short passwords stay brute-forceable.", HasRegistryPath = false },
        new SubCheck { Id = "PWD-001.5", Title = "Password must meet complexity requirements", Expected = "Enabled",
            WhatItDoes = "Requires mixed character classes.", Recommendation = "Enabled.",
            CheckCurrentCli = "# secpol.msc", CliCommand = "# secpol.msc → Password Policy → Complexity = Enabled",
            VerifyCli = "# secpol.msc", Verification = "'Password must meet complexity requirements' shows Enabled.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Complexity requirements",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Password must meet complexity requirements",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Password must meet complexity requirements > Enabled",
            GraphicalSteps = "1) secpol.msc → Account Policies → Password Policy. 2) Double-click complexity setting. 3) Enable.",
            UndoCli = "# revert", IgnoreConsequence = "Simple passwords allowed.", HasRegistryPath = false },
        new SubCheck { Id = "PWD-001.6", Title = "Store passwords using reversible encryption", Expected = "Disabled",
            WhatItDoes = "Prevents weak recoverable storage.", Recommendation = "Disabled.",
            CheckCurrentCli = "# secpol.msc", CliCommand = "# secpol.msc → Password Policy → Reversible encryption = Disabled",
            VerifyCli = "# secpol.msc", Verification = "'Store passwords using reversible encryption' shows Disabled.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Password Policy → Reversible encryption",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Store passwords using reversible encryption",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Store passwords using reversible encryption > Disabled",
            GraphicalSteps = "1) secpol.msc → Account Policies → Password Policy. 2) Double-click reversible encryption. 3) Disable.",
            UndoCli = "# revert", IgnoreConsequence = "Passwords stored in a recoverable form.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            string output = Run("net", "accounts");
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("Minimum password length", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var num = new string(line.Where(char.IsDigit).ToArray());
                if (int.TryParse(num, out int len))
                {
                    currentValue = $"{len} characters";
                    status = len >= 14 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "0 characters";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Not available";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "14 characters", "Enforce strong password policies to prevent weak credentials.",
            errorMessage: errorMessage,
            description: "Defines rules for password strength, age, and history.",
            registryPath: null, cisReference: "CIS 1.1", riskScore: 80, sourceType: "net accounts",
            sourceCommand: "net accounts", fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }

    // EDIT (فاز 1 - پیام 3): Test 3 اصلاح شد — PowerShell parser برای همه 6 پارامتر Password Policy
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: net accounts (CMD) - بدون تغییر
        try
        {
            string output = Run("net", "accounts");
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("Minimum password length", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var num = new string(line.Where(char.IsDigit).ToArray());
                if (int.TryParse(num, out int len))
                {
                    var passed = len >= 14;
                    results.Add(new TestResult("Primary", "net accounts", passed, $"Minimum password length = {len}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "net accounts", false, "Could not parse length"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "net accounts", false, "Minimum password length not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "net accounts", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: secedit /export - بدون تغییر
        try
        {
            if (!Directory.Exists(@"C:\temp"))
            {
                Directory.CreateDirectory(@"C:\temp");
            }

            var psi = new ProcessStartInfo("secedit.exe", "/export /cfg \"C:\\temp\\password.inf\" /areas SECURITYPOLICY")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (File.Exists(@"C:\temp\password.inf"))
            {
                var content = await File.ReadAllTextAsync(@"C:\temp\password.inf");
                var line = content.Split('\n').FirstOrDefault(l => l.Contains("MinimumPasswordLength", StringComparison.OrdinalIgnoreCase));
                if (line != null)
                {
                    var parts = line.Split('=');
                    if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int len))
                    {
                        var passed = len >= 14;
                        results.Add(new TestResult("Cross-check", "secedit", passed, $"MinimumPasswordLength = {len}"));
                    }
                    else
                    {
                        results.Add(new TestResult("Cross-check", "secedit", false, "Could not parse MinimumPasswordLength"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "secedit", false, "MinimumPasswordLength not found"));
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

        // Test 3 (CORRECTED): PowerShell parsing all 6 password policy parameters from net accounts
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-Command \"$o = net accounts; $history = ($o | Select-String 'password history').ToString().Split(':')[-1].Trim(); $maxAge = ($o | Select-String 'Maximum password age').ToString().Split(':')[-1].Trim(); $minAge = ($o | Select-String 'Minimum password age').ToString().Split(':')[-1].Trim(); $minLen = ($o | Select-String 'Minimum password length').ToString().Split(':')[-1].Trim(); Write-Output \\\"H=$history|MaxA=$maxAge|MinA=$minAge|MinL=$minLen\\\"\"")
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
                    // Parse: H=24|MaxA=60|MinA=1|MinL=14
                    var parts = output.Trim().Split('|');
                    if (parts.Length >= 4)
                    {
                        var hVal = new string(parts[0].Replace("H=", "").Where(char.IsDigit).ToArray());
                        var maxVal = new string(parts[1].Replace("MaxA=", "").Where(char.IsDigit).ToArray());
                        var minAgeVal = new string(parts[2].Replace("MinA=", "").Where(char.IsDigit).ToArray());
                        var minLenVal = new string(parts[3].Replace("MinL=", "").Where(char.IsDigit).ToArray());

                        var valid = int.TryParse(hVal, out int h) &&
                                    int.TryParse(maxVal, out int maxAge) &&
                                    int.TryParse(minAgeVal, out int minAge) &&
                                    int.TryParse(minLenVal, out int minLen);

                        if (valid)
                        {
                            var passed = h >= 24 && maxAge <= 60 && maxAge > 0 && minAge >= 1 && minLen >= 14;
                            results.Add(new TestResult(
                                "Verification",
                                "PowerShell (password policy full)",
                                passed,
                                $"history={h}, maxAge={maxAge}d, minAge={minAge}d, minLen={minLen}"));
                        }
                        else
                        {
                            results.Add(new TestResult(
                                "Verification",
                                "PowerShell (password policy full)",
                                false,
                                $"Could not parse: {output.Trim()}"));
                        }
                    }
                    else
                    {
                        results.Add(new TestResult(
                            "Verification",
                            "PowerShell (password policy full)",
                            false,
                            $"Unexpected output: {output.Trim()}"));
                    }
                }
                else
                {
                    results.Add(new TestResult(
                        "Verification",
                        "PowerShell (password policy full)",
                        false,
                        "Empty output"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult(
                "Verification",
                "PowerShell (password policy full)",
                false,
                $"Error: {ex.Message}"));
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