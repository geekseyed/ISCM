using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AccountLockoutCheck : IHardeningCheck
{
    public string CheckId => "LCK-001";
    public string Name => "Account Lockout Policy";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Medium;

    // Paths verified against Revised PDF (item 2): Account Policies > Account Lockout Policy.
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
            YouAreHere = "secpol.msc → Security Settings → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > 'Account lockout threshold' > 5 invalid logon attempts",
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
            YouAreHere = "secpol.msc → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > 'Account lockout duration' > 15 minutes",
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
            YouAreHere = "secpol.msc → Account Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > 'Reset account lockout counter after' > 15 minutes",
            GraphicalSteps = "1) Account Lockout Policy. 2) 'Reset account lockout counter after' = 15.",
            UndoCli = "net accounts /lockoutwindow:0", IgnoreConsequence = "Counter may reset too fast/slow.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            string output = Run("net", "accounts");
            var line = output.Split('\n').FirstOrDefault(l => l.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var num = new string(line.Where(char.IsDigit).ToArray());
                if (int.TryParse(num, out int t)) { currentValue = t == 0 ? "Never" : t.ToString(); status = t >= 5 ? CheckStatus.Pass : CheckStatus.Fail; }
                else { currentValue = "Never"; status = CheckStatus.Fail; }
            }
            else { currentValue = "Not available"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "5", "Lock accounts after repeated failed logons to mitigate brute-force attacks.",
            errorMessage: errorMessage,
            description: "Locks user accounts after repeated failed logon attempts.",
            registryPath: null, cisReference: "CIS 5.4", riskScore: 60, sourceType: "net accounts",
            sourceCommand: "net accounts", fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
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