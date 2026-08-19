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

    // Revised PDF item 7: all 9 rights under Local Policies > User Rights Assignment.
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "URA-001.1", Title = "Access this computer from the network", Expected = "Administrators, Remote Desktop Users", WhatItDoes = "Restricts network logon to approved groups.", Recommendation = "Only Admins + RDP Users.",
            CheckCurrentCli = "# secpol.msc → User Rights Assignment → Access this computer from the network", CliCommand = "# secpol.msc → set to Administrators, Remote Desktop Users", VerifyCli = "# secpol.msc → verify members", Verification = "Only Administrators + Remote Desktop Users listed.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Access from network",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Access this computer from the network",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment",
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Access this computer from the network' > Administrators, Remote Desktop Users",
            GraphicalSteps = "1) secpol.msc → Local Policies → User Rights Assignment. 2) Double-click 'Access this computer from the network'. 3) Keep only Administrators + Remote Desktop Users.",
            UndoCli = "# restore prior groups", IgnoreConsequence = "Excess accounts can log on over the network.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.2", Title = "Deny access to this computer from the network", Expected = "Guests, Local account, Everyone (where appropriate)", WhatItDoes = "Blocks risky accounts from network access.", Recommendation = "Add Guests + Local account.",
            CheckCurrentCli = "# secpol.msc → Deny access to this computer from the network", CliCommand = "# secpol.msc → add Guests, Local account", VerifyCli = "# secpol.msc → verify", Verification = "Guests + Local account present.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny network access",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny access to this computer from the network",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny access to this computer from the network' > Guests, Local account",
            GraphicalSteps = "1) User Rights Assignment. 2) 'Deny access to this computer from the network'. 3) Add Guests + Local account.",
            UndoCli = "# remove entries", IgnoreConsequence = "Guest/local accounts reachable over network.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.3", Title = "Deny log on as a batch job", Expected = "Guests", WhatItDoes = "Stops Guest batch/scheduled jobs.", Recommendation = "Add Guests.",
            CheckCurrentCli = "# secpol.msc → Deny log on as a batch job", CliCommand = "# secpol.msc → add Guests", VerifyCli = "# verify", Verification = "Guests present.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny batch job",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny log on as a batch job",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on as a batch job' > Guests",
            GraphicalSteps = "1) 'Deny log on as a batch job'. 2) Add Guests.", UndoCli = "# remove", IgnoreConsequence = "Guest may run scheduled jobs.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.4", Title = "Deny log on as a service", Expected = "Guests", WhatItDoes = "Stops Guest as service identity.", Recommendation = "Add Guests.",
            CheckCurrentCli = "# secpol.msc → Deny log on as a service", CliCommand = "# secpol.msc → add Guests", VerifyCli = "# verify", Verification = "Guests present.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny service",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny log on as a service",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on as a service' > Guests",
            GraphicalSteps = "1) 'Deny log on as a service'. 2) Add Guests.", UndoCli = "# remove", IgnoreConsequence = "Guest usable as service identity.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.5", Title = "Deny log on locally", Expected = "Guests", WhatItDoes = "Blocks Guest console logon.", Recommendation = "Add Guests.",
            CheckCurrentCli = "# secpol.msc → Deny log on locally", CliCommand = "# secpol.msc → add Guests", VerifyCli = "# verify", Verification = "Guests present.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny local logon",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny log on locally",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on locally' > Guests",
            GraphicalSteps = "1) 'Deny log on locally'. 2) Add Guests.", UndoCli = "# remove", IgnoreConsequence = "Guest can log on at console.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.6", Title = "Deny log on through Remote Desktop Services", Expected = "Guests, Local account", WhatItDoes = "Blocks Guest/local RDP.", Recommendation = "Add Guests + Local account.",
            CheckCurrentCli = "# secpol.msc → Deny log on through RDS", CliCommand = "# secpol.msc → add Guests, Local account", VerifyCli = "# verify", Verification = "Guests + Local account present.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Deny RDP",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Deny log on through Remote Desktop Services",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Deny log on through Remote Desktop Services' > Guests, Local account",
            GraphicalSteps = "1) 'Deny log on through Remote Desktop Services'. 2) Add Guests + Local account.", UndoCli = "# remove", IgnoreConsequence = "Guest/local RDP access possible.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.7", Title = "Allow log on through Remote Desktop Services", Expected = "Administrators, Remote Desktop Users", WhatItDoes = "Limits RDP to approved groups.", Recommendation = "Only Admins + RDP Users.",
            CheckCurrentCli = "# secpol.msc → Allow log on through RDS", CliCommand = "# secpol.msc → set Admins + RDP Users", VerifyCli = "# verify", Verification = "Only approved groups.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Allow RDP",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Allow log on through Remote Desktop Services",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Allow log on through Remote Desktop Services' > Administrators, Remote Desktop Users",
            GraphicalSteps = "1) 'Allow log on through Remote Desktop Services'. 2) Keep Admins + RDP Users.", UndoCli = "# restore", IgnoreConsequence = "Unapproved RDP access.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.8", Title = "Debug programs", Expected = "Administrators only", WhatItDoes = "Restricts dangerous debug right.", Recommendation = "Administrators only.",
            CheckCurrentCli = "# secpol.msc → Debug programs", CliCommand = "# secpol.msc → Administrators only", VerifyCli = "# verify", Verification = "Only Administrators.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Debug programs",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Debug programs",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Debug programs' > Administrators only",
            GraphicalSteps = "1) 'Debug programs'. 2) Administrators only.", UndoCli = "# restore", IgnoreConsequence = "Debug right enables process memory reads.", HasRegistryPath = false },
        new SubCheck { Id = "URA-001.9", Title = "Take ownership of files or other objects", Expected = "Administrators only", WhatItDoes = "Limits ownership seizure.", Recommendation = "Administrators only.",
            CheckCurrentCli = "# secpol.msc → Take ownership", CliCommand = "# secpol.msc → Administrators only", VerifyCli = "# verify", Verification = "Only Administrators.",
            ConsoleTool = "secpol.msc", DestinationLabel = "User Rights → Take ownership",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Take ownership of files or other objects",
            ConsolePath = "… > Local Policies > User Rights Assignment", YouAreHere = "secpol.msc → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Take ownership of files or other objects' > Administrators only",
            GraphicalSteps = "1) 'Take ownership of files or other objects'. 2) Administrators only.", UndoCli = "# restore", IgnoreConsequence = "Non-admins can seize ownership.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, CheckStatus.Warning,
            "Manual review required", "Per PDF baseline",
            "Review User Rights Assignment against the baseline (secpol.msc).",
            errorMessage: null,
            description: "Controls which groups may perform sensitive system operations.",
            registryPath: null, cisReference: "CIS 2.2", riskScore: 55, sourceType: "secpol.msc",
            sourceCommand: "secpol.msc → User Rights Assignment", fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }
}