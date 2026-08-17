using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AdvancedAuditCheck : IHardeningCheck
{
    public string CheckId => "AUD-001";
    public string Name => "Advanced Audit Policy";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "AUD-001.1", Title = "Audit Logon", Expected = "Success and Failure", WhatItDoes = "Logs every successful/failed logon.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable", Verification = "auditpol /get /subcategory:\"Logon\" → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Logon", YouAreHere = "Audit Policy (root)", GoTo = "Logon/Logoff → Audit Logon → S+F", GraphicalSteps = "1) Audit Logon → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.2", Title = "Audit Logoff", Expected = "Success", WhatItDoes = "Logs logoff events.", Recommendation = "Enable Success.", CliCommand = "auditpol /set /subcategory:\"Logoff\" /success:enable", Verification = "auditpol → Logoff → Success.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Logoff", YouAreHere = "Audit Policy (root)", GoTo = "Logon/Logoff → Audit Logoff → Success", GraphicalSteps = "1) Audit Logoff → Success.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.3", Title = "Audit Special Logon", Expected = "Success and Failure", WhatItDoes = "Logs privileged logons.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Special Logon\" /success:enable /failure:enable", Verification = "auditpol → Special Logon → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Special Logon", YouAreHere = "Audit Policy (root)", GoTo = "Logon/Logoff → Special Logon → S+F", GraphicalSteps = "1) Special Logon → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.4", Title = "Audit Credential Validation", Expected = "Success and Failure", WhatItDoes = "Logs credential checks.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable", Verification = "auditpol → Credential Validation → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Credential Validation", YouAreHere = "Audit Policy (root)", GoTo = "Account Logon → Credential Validation → S+F", GraphicalSteps = "1) Credential Validation → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.5", Title = "Audit User Account Management", Expected = "Success and Failure", WhatItDoes = "Logs user create/modify.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"User Account Management\" /success:enable /failure:enable", Verification = "auditpol → User Account Mgmt → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → User Account Mgmt", YouAreHere = "Audit Policy (root)", GoTo = "Account Management → User Account Mgmt → S+F", GraphicalSteps = "1) User Account Mgmt → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.6", Title = "Audit Security Group Management", Expected = "Success and Failure", WhatItDoes = "Logs group changes.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Security Group Management\" /success:enable /failure:enable", Verification = "auditpol → Security Group Mgmt → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Security Group Mgmt", YouAreHere = "Audit Policy (root)", GoTo = "Account Management → Security Group Mgmt → S+F", GraphicalSteps = "1) Security Group Mgmt → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.7", Title = "Audit Process Creation", Expected = "Success", WhatItDoes = "Logs new processes (4688).", Recommendation = "Enable Success.", CliCommand = "auditpol /set /subcategory:\"Process Creation\" /success:enable", Verification = "auditpol → Process Creation → Success.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Process Creation", YouAreHere = "Audit Policy (root)", GoTo = "Detailed Tracking → Process Creation → Success", GraphicalSteps = "1) Process Creation → Success.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.8", Title = "Audit Authentication Policy Change", Expected = "Success and Failure", WhatItDoes = "Logs auth policy changes.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Authentication Policy Change\" /success:enable /failure:enable", Verification = "auditpol → Auth Policy Change → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Auth Policy Change", YouAreHere = "Audit Policy (root)", GoTo = "Policy Change → Auth Policy Change → S+F", GraphicalSteps = "1) Auth Policy Change → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.9", Title = "Audit Authorization Policy Change", Expected = "Success and Failure", WhatItDoes = "Logs user-rights changes.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Authorization Policy Change\" /success:enable /failure:enable", Verification = "auditpol → Authz Policy Change → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Authz Policy Change", YouAreHere = "Audit Policy (root)", GoTo = "Policy Change → Authz Policy Change → S+F", GraphicalSteps = "1) Authz Policy Change → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.10", Title = "Audit Security State Change", Expected = "Success and Failure", WhatItDoes = "Logs startup/shutdown.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Security State Change\" /success:enable /failure:enable", Verification = "auditpol → Security State Change → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Security State Change", YouAreHere = "Audit Policy (root)", GoTo = "System → Security State Change → S+F", GraphicalSteps = "1) Security State Change → S+F.", HasRegistryPath = false },
        new SubCheck { Id = "AUD-001.11", Title = "Audit Security System Extension", Expected = "Success and Failure", WhatItDoes = "Logs security extension loads.", Recommendation = "Enable S+F.", CliCommand = "auditpol /set /subcategory:\"Security System Extension\" /success:enable /failure:enable", Verification = "auditpol → Security System Extension → S+F.", ConsoleTool = "secpol.msc", DestinationLabel = "Advanced Audit → Security System Extension", YouAreHere = "Audit Policy (root)", GoTo = "System → Security System Extension → S+F", GraphicalSteps = "1) Security System Extension → S+F.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            string output = Run("auditpol", "/get /category:* /r");
            if (output.Contains("Success and Failure")) { currentValue = "Configured"; status = CheckStatus.Pass; }
            else { currentValue = "Not configured"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Warning; currentValue = "Manual review required"; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Success and Failure",
            "Enable granular audit policies for monitoring and forensics.",
            errorMessage: errorMessage,
            description: "Enables detailed security-event logging across logon, account, policy and system categories.",
            registryPath: null,
            cisReference: "CIS 6.2",
            riskScore: 50,
            sourceType: "auditpol",
            sourceCommand: "auditpol /get /category:*",
            fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args)
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return o;
        }
        catch { return ""; }
    }
}