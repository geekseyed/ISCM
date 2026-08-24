using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AdvancedAuditCheck : IHardeningCheck, IMultiPathCheck
{
    public string CheckId => "AUD-001";
    public string Name => "Advanced Audit Policy";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    // SubChecks definitions preserved exactly as provided (11 items)
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "AUD-001.1", Title = "Audit Logon", Expected = "Success and Failure", WhatItDoes = "Logs successful and failed user logons.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Logon\"", CliCommand = "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Logon\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Logon/Logoff → Audit Logon", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Logon", ConsolePath = "… > System Audit Policies > Logon/Logoff", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Logon > Success and Failure", GraphicalSteps = "1) secpol.msc → Advanced Audit → System Audit Policies → Logon/Logoff. 2) 'Audit Logon' → S+F.", UndoCli = "auditpol /set /subcategory:\"Logon\" /success:disable /failure:disable", IgnoreConsequence = "No logon trail.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.2", Title = "Audit Logoff", Expected = "Success", WhatItDoes = "Logs user logoff events.", Recommendation = "Enable Success.", CheckCurrentCli = "auditpol /get /subcategory:\"Logoff\"", CliCommand = "auditpol /set /subcategory:\"Logoff\" /success:enable", VerifyCli = "auditpol /get /subcategory:\"Logoff\"", Verification = "Success enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Logon/Logoff → Audit Logoff", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Logoff", ConsolePath = "… > System Audit Policies > Logon/Logoff", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Logoff > Success", GraphicalSteps = "1) Logon/Logoff. 2) 'Audit Logoff' → Success.", UndoCli = "auditpol /set /subcategory:\"Logoff\" /success:disable", IgnoreConsequence = "No logoff trail.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.3", Title = "Audit Special Logon", Expected = "Success and Failure", WhatItDoes = "Highlights privileged logons.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Special Logon\"", CliCommand = "auditpol /set /subcategory:\"Special Logon\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Special Logon\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Logon/Logoff → Audit Special Logon", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Special Logon", ConsolePath = "… > System Audit Policies > Logon/Logoff", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff > Audit Special Logon > Success and Failure", GraphicalSteps = "1) Logon/Logoff. 2) 'Audit Special Logon' → S+F.", UndoCli = "auditpol /set /subcategory:\"Special Logon\" /success:disable /failure:disable", IgnoreConsequence = "Privileged logons untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.4", Title = "Audit Credential Validation", Expected = "Success and Failure", WhatItDoes = "Logs credential checks on the authenticating system.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Credential Validation\"", CliCommand = "auditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Credential Validation\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Account Logon → Credential Validation", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Logon > Audit Credential Validation", ConsolePath = "… > System Audit Policies > Account Logon", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Logon > Audit Credential Validation > Success and Failure", GraphicalSteps = "1) Account Logon. 2) 'Audit Credential Validation' → S+F.", UndoCli = "auditpol /set /subcategory:\"Credential Validation\" /success:disable /failure:disable", IgnoreConsequence = "Credential attempts untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.5", Title = "Audit User Account Management", Expected = "Success and Failure", WhatItDoes = "Logs account create/modify/delete.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"User Account Management\"", CliCommand = "auditpol /set /subcategory:\"User Account Management\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"User Account Management\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Account Management → User Account Mgmt", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Management > Audit User Account Management", ConsolePath = "… > System Audit Policies > Account Management", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Management > Audit User Account Management > Success and Failure", GraphicalSteps = "1) Account Management. 2) 'Audit User Account Management' → S+F.", UndoCli = "auditpol /set /subcategory:\"User Account Management\" /success:disable /failure:disable", IgnoreConsequence = "Account changes untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.6", Title = "Audit Security Group Management", Expected = "Success and Failure", WhatItDoes = "Logs security-group changes.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Security Group Management\"", CliCommand = "auditpol /set /subcategory:\"Security Group Management\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Security Group Management\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Account Management → Security Group Mgmt", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Management > Audit Security Group Management", ConsolePath = "… > System Audit Policies > Account Management", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Account Management > Audit Security Group Management > Success and Failure", GraphicalSteps = "1) Account Management. 2) 'Audit Security Group Management' → S+F.", UndoCli = "auditpol /set /subcategory:\"Security Group Management\" /success:disable /failure:disable", IgnoreConsequence = "Group changes untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.7", Title = "Audit Process Creation", Expected = "Success", WhatItDoes = "Logs each new process (4688).", Recommendation = "Enable Success.", CheckCurrentCli = "auditpol /get /subcategory:\"Process Creation\"", CliCommand = "auditpol /set /subcategory:\"Process Creation\" /success:enable", VerifyCli = "auditpol /get /subcategory:\"Process Creation\"", Verification = "Success enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Detailed Tracking → Process Creation", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking > Audit Process Creation", ConsolePath = "… > System Audit Policies > Detailed Tracking", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking > Audit Process Creation > Success", GraphicalSteps = "1) Detailed Tracking. 2) 'Audit Process Creation' → Success.", UndoCli = "auditpol /set /subcategory:\"Process Creation\" /success:disable", IgnoreConsequence = "No process trail.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.8", Title = "Audit Authentication Policy Change", Expected = "Success and Failure", WhatItDoes = "Logs auth-policy changes.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Authentication Policy Change\"", CliCommand = "auditpol /set /subcategory:\"Authentication Policy Change\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Authentication Policy Change\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Policy Change → Auth Policy Change", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Policy Change > Audit Authentication Policy Change", ConsolePath = "… > System Audit Policies > Policy Change", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Policy Change > Audit Authentication Policy Change > Success and Failure", GraphicalSteps = "1) Policy Change. 2) 'Audit Authentication Policy Change' → S+F.", UndoCli = "auditpol /set /subcategory:\"Authentication Policy Change\" /success:disable /failure:disable", IgnoreConsequence = "Auth changes untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.9", Title = "Audit Authorization Policy Change", Expected = "Success and Failure", WhatItDoes = "Logs user-rights changes.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Authorization Policy Change\"", CliCommand = "auditpol /set /subcategory:\"Authorization Policy Change\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Authorization Policy Change\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Policy Change → Authz Policy Change", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Policy Change > Audit Authorization Policy Change", ConsolePath = "… > System Audit Policies > Policy Change", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Policy Change > Audit Authorization Policy Change > Success and Failure", GraphicalSteps = "1) Policy Change. 2) 'Audit Authorization Policy Change' → S+F.", UndoCli = "auditpol /set /subcategory:\"Authorization Policy Change\" /success:disable /failure:disable", IgnoreConsequence = "Rights changes untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.10", Title = "Audit Security State Change", Expected = "Success and Failure", WhatItDoes = "Logs startup/shutdown/state changes.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Security State Change\"", CliCommand = "auditpol /set /subcategory:\"Security State Change\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Security State Change\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → System → Security State Change", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > System > Audit Security State Change", ConsolePath = "… > System Audit Policies > System", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > System > Audit Security State Change > Success and Failure", GraphicalSteps = "1) System. 2) 'Audit Security State Change' → S+F.", UndoCli = "auditpol /set /subcategory:\"Security State Change\" /success:disable /failure:disable", IgnoreConsequence = "State changes untracked.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.11", Title = "Audit Security System Extension", Expected = "Success and Failure", WhatItDoes = "Logs security-extension loads.", Recommendation = "Enable S+F.", CheckCurrentCli = "auditpol /get /subcategory:\"Security System Extension\"", CliCommand = "auditpol /set /subcategory:\"Security System Extension\" /success:enable /failure:enable", VerifyCli = "auditpol /get /subcategory:\"Security System Extension\"", Verification = "S+F enabled.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → System → Security System Extension", GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > System > Audit Security System Extension", ConsolePath = "… > System Audit Policies > System", YouAreHere = "secpol.msc → Advanced Audit → System Audit Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > System > Audit Security System Extension > Success and Failure", GraphicalSteps = "1) System. 2) 'Audit Security System Extension' → S+F.", UndoCli = "auditpol /set /subcategory:\"Security System Extension\" /success:disable /failure:disable", IgnoreConsequence = "Extension loads untracked.", HasRegistryPath = false }
    };

    public async Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();
        string details = "";

        try
        {
            // Run auditpol once for all categories
            string output = Run("auditpol", "/get /category:*");
            if (string.IsNullOrEmpty(output)) return new Finding(CheckId, Name, Category, Severity, CheckStatus.Error, "No output", "N/A", "Error", subChecks: SubChecks);

            // Define expected states for each subcategory
            var checks = new Dictionary<string, string>
            {
                { "Logon", "Success and Failure" },
                { "Logoff", "Success" },
                { "Special Logon", "Success and Failure" },
                { "Credential Validation", "Success and Failure" },
                { "User Account Management", "Success and Failure" },
                { "Security Group Management", "Success and Failure" },
                { "Process Creation", "Success" },
                { "Authentication Policy Change", "Success and Failure" },
                { "Authorization Policy Change", "Success and Failure" },
                { "Security State Change", "Success and Failure" },
                { "Security System Extension", "Success and Failure" }
            };

            foreach (var check in checks)
            {
                // Find the line in output. Format: "    Subcategory : Value"
                // We look for the subcategory name and check the value on the same or next line
                // Simplified parsing: look for "SubcategoryName" and then check for "Success" or "Failure" nearby
                // A robust way is to split by lines and find the index.

                // Since auditpol output is tricky, we'll use a simple contains check for the specific setting
                // Note: This is a simplified parser. A real one would parse the structured output.
                // For now, we assume if the specific string "SubcategoryName" is followed by the expected value in the block.

                // Better approach: Split output into blocks by empty lines or just search for the specific subcategory line
                var lines = output.Split('\n');
                bool found = false;
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Contains(check.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        // The value is usually on the same line after a colon or on the next line
                        string context = lines[i];
                        if (i + 1 < lines.Length) context += lines[i + 1];

                        if (context.Contains(check.Value, StringComparison.OrdinalIgnoreCase))
                        {
                            statuses.Add(CheckStatus.Pass);
                            found = true;
                        }
                        else
                        {
                            statuses.Add(CheckStatus.Fail);
                            found = true;
                        }
                        break;
                    }
                }
                if (!found) statuses.Add(CheckStatus.Unknown);
            }

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            details = $"{passCount}/{checks.Count} configured correctly";

            return new Finding(CheckId, Name, Category, Severity, finalStatus, details, "All 11 subcategories configured", "Enable granular audit policies.", description: "Enables detailed security-event logging.", cisReference: "CIS 6.2", riskScore: 50, sourceType: "auditpol", sourceCommand: "auditpol /get /category:*", fixTools: new List<string> { "secpol.msc" }, subChecks: SubChecks);
        }
        catch (Exception ex) { return new Finding(CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error", errorMessage: ex.Message, subChecks: SubChecks); }
    }

    // Preserved: 3-Test Verification
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: auditpol Logon
        try { string output = Run("auditpol", "/get /subcategory:\"Logon\""); var passed = output.Contains("Success and Failure", StringComparison.OrdinalIgnoreCase); results.Add(new TestResult("Primary", "auditpol (Logon)", passed, passed ? "Logon audit: Success and Failure" : "Logon audit not fully configured")); } catch (Exception ex) { results.Add(new TestResult("Primary", "auditpol (Logon)", false, $"Error: {ex.Message}")); }
        await Task.Delay(50);
        // Test 2: auditpol Process Creation
        try { string output = Run("auditpol", "/get /subcategory:\"Process Creation\""); var passed = output.Contains("Success", StringComparison.OrdinalIgnoreCase); results.Add(new TestResult("Cross-check", "auditpol (Process Creation)", passed, passed ? "Process Creation audit: Success enabled" : "Process Creation audit not enabled")); } catch (Exception ex) { results.Add(new TestResult("Cross-check", "auditpol (Process Creation)", false, $"Error: {ex.Message}")); }
        await Task.Delay(50);
        // Test 3: PowerShell Get-WinEvent
        try { var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated\"") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true }; using var process = Process.Start(psi); var output = await process.StandardOutput.ReadToEndAsync(); await process.WaitForExitAsync(); var passed = !string.IsNullOrWhiteSpace(output); results.Add(new TestResult("Verification", "Get-WinEvent (4624)", passed, passed ? $"Last logon event: {output.Trim()}" : "No recent logon events found")); } catch (Exception ex) { results.Add(new TestResult("Verification", "Get-WinEvent (4624)", false, $"Error: {ex.Message}")); }
        return results;
    }

    private static CheckStatus GetWorstStatus(IEnumerable<CheckStatus> statuses) { if (statuses.Any(s => s == CheckStatus.Fail)) return CheckStatus.Fail; if (statuses.Any(s => s == CheckStatus.Error)) return CheckStatus.Error; if (statuses.Any(s => s == CheckStatus.Unknown)) return CheckStatus.Unknown; return CheckStatus.Pass; }
    private static string Run(string cmd, string args) { try { var psi = new ProcessStartInfo(cmd, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true }; using var p = Process.Start(psi); if (p == null) return ""; string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(3000); return o; } catch { return ""; } }
}