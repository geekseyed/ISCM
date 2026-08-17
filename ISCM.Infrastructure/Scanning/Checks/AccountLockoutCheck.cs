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

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "LCK-001.1", Title = "Account lockout threshold", Expected = "5 invalid attempts",
            WhatItDoes = "Number of failed logons before the account is locked.",
            Recommendation = "Set threshold to 5.",
            CliCommand = "net accounts /lockoutthreshold:5",
            Verification = "Run: net accounts → 'Lockout threshold' shows 5.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Threshold",
            YouAreHere = "Local Security Policy (root) → Account Policies", GoTo = "Account Lockout Policy → Threshold = 5",
            GraphicalSteps = "1) secpol.msc → Account Policies → Account Lockout Policy. 2) Threshold = 5.",
            HasRegistryPath = false },
        new SubCheck { Id = "LCK-001.2", Title = "Account lockout duration", Expected = "15 minutes",
            WhatItDoes = "How long the account stays locked after threshold is reached.",
            Recommendation = "Set duration to 15.",
            CliCommand = "net accounts /lockoutduration:15",
            Verification = "net accounts → 'Lockout duration' shows 15.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Duration",
            YouAreHere = "Local Security Policy (root) → Account Policies", GoTo = "Account Lockout Policy → Duration = 15",
            GraphicalSteps = "1) Duration = 15 minutes.",
            HasRegistryPath = false },
        new SubCheck { Id = "LCK-001.3", Title = "Reset account lockout counter after", Expected = "15 minutes",
            WhatItDoes = "Time before the failed-attempt counter resets to zero.",
            Recommendation = "Set reset window to 15.",
            CliCommand = "net accounts /lockoutwindow:15",
            Verification = "net accounts → 'Lockout observation window' shows 15.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Account Lockout Policy → Reset counter",
            YouAreHere = "Local Security Policy (root) → Account Policies", GoTo = "Account Lockout Policy → Reset counter = 15",
            GraphicalSteps = "1) 'Reset account lockout counter after' = 15.",
            HasRegistryPath = false }
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
                if (int.TryParse(num, out int threshold))
                {
                    currentValue = threshold == 0 ? "Never" : threshold.ToString();
                    status = (threshold >= 5) ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else { currentValue = "Never"; status = CheckStatus.Fail; }
            }
            else { currentValue = "Not available"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue,
            "5", "Lock accounts after repeated failed logons to mitigate brute-force attacks.",
            errorMessage: errorMessage,
            description: "Locks user accounts after repeated failed logon attempts.",
            registryPath: null,
            cisReference: "CIS 5.4", riskScore: 60, sourceType: "net accounts",
            sourceCommand: "net accounts",
            fixTools: new List<string> { "secpol.msc" }, subChecks: SubChecks));
    }

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args)
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return output;
        }
        catch { return ""; }
    }
}