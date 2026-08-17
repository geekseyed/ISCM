using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Infrastructure.Scanning.Checks;

public class UserRightsCheck : IHardeningCheck
{
    public string CheckId => "URA-001";
    public string Name => "User Rights Assignment";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "URA-001.1", Title = "Access this computer from the network", Expected = "Administrators, Remote Desktop Users", WhatItDoes = "Restricts network logon.", Recommendation = "Limit to required groups.", CliCommand = "# secpol.msc → User Rights Assignment → 'Access this computer from the network'", Verification = "secpol → only Administrators + RDP Users listed.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Network access", YouAreHere = "Local Security Policy (root) → Local Policies", GoTo = "User Rights Assignment → Access from network", GraphicalSteps = "1) Edit 'Access this computer from the network'.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.2", Title = "Deny access to this computer from the network", Expected = "Guests, Local account", WhatItDoes = "Blocks risky accounts over network.", Recommendation = "Add Guests + Local account.", CliCommand = "# secpol.msc → 'Deny access to this computer from the network'", Verification = "Guests + Local account present.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny network", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Deny network access", GraphicalSteps = "1) Add Guests, Local account.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.3", Title = "Deny log on as a batch job", Expected = "Guests", WhatItDoes = "Stops Guest batch jobs.", Recommendation = "Add Guests.", CliCommand = "# secpol.msc → 'Deny log on as a batch job'", Verification = "Guests present.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny batch", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Deny batch job", GraphicalSteps = "1) Add Guests.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.4", Title = "Deny log on as a service", Expected = "Guests", WhatItDoes = "Stops Guest as service.", Recommendation = "Add Guests.", CliCommand = "# secpol.msc → 'Deny log on as a service'", Verification = "Guests present.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny service", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Deny service", GraphicalSteps = "1) Add Guests.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.5", Title = "Deny log on locally", Expected = "Guests", WhatItDoes = "Blocks Guest console logon.", Recommendation = "Add Guests.", CliCommand = "# secpol.msc → 'Deny log on locally'", Verification = "Guests present.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny local", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Deny local logon", GraphicalSteps = "1) Add Guests.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.6", Title = "Deny log on through RDP", Expected = "Guests, Local account", WhatItDoes = "Blocks Guest/local RDP.", Recommendation = "Add Guests + Local account.", CliCommand = "# secpol.msc → 'Deny log on through Remote Desktop Services'", Verification = "Guests + Local account present.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny RDP", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Deny RDP", GraphicalSteps = "1) Add Guests, Local account.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.7", Title = "Allow log on through RDP", Expected = "Administrators, RDP Users", WhatItDoes = "Limits RDP to approved groups.", Recommendation = "Only Admins + RDP Users.", CliCommand = "# secpol.msc → 'Allow log on through Remote Desktop Services'", Verification = "Only approved groups.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Allow RDP", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Allow RDP", GraphicalSteps = "1) Set Admins + RDP Users.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.8", Title = "Debug programs", Expected = "Administrators only", WhatItDoes = "Restricts dangerous debug right.", Recommendation = "Administrators only.", CliCommand = "# secpol.msc → 'Debug programs'", Verification = "Only Administrators.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Debug programs", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Debug programs", GraphicalSteps = "1) Administrators only.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.9", Title = "Take ownership of files/objects", Expected = "Administrators only", WhatItDoes = "Limits ownership seizure.", Recommendation = "Administrators only.", CliCommand = "# secpol.msc → 'Take ownership of files or other objects'", Verification = "Only Administrators.", ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Take ownership", YouAreHere = "Local Security Policy (root)", GoTo = "User Rights → Take ownership", GraphicalSteps = "1) Administrators only.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, CheckStatus.Warning,
            "Manual review required", "Per PDF baseline",
            "Review User Rights Assignment against the baseline (secpol.msc).",
            errorMessage: null,
            description: "Controls which groups may perform sensitive system operations.",
            registryPath: null,
            cisReference: "CIS 2.2",
            riskScore: 55,
            sourceType: "secpol.msc",
            sourceCommand: "secpol.msc → User Rights Assignment",
            fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }
}