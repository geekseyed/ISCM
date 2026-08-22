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

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: net accounts (CMD)
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

        // Test 2: secedit /export با ایجاد پوشه
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

        // Test 3: PowerShell Get-LocalUser
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-LocalUser | Select-Object -ExpandProperty PasswordRequired | Select-Object -First 1\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = !string.IsNullOrWhiteSpace(output) && output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            results.Add(new TestResult("Verification", "PowerShell Get-LocalUser", passed, passed ? "PasswordRequired = True" : "Password policy query successful"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "PowerShell Get-LocalUser", false, $"Error: {ex.Message}"));
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