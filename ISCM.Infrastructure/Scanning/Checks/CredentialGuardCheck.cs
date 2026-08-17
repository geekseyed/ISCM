using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class CredentialGuardCheck : IHardeningCheck
{
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string DgPath = @"SYSTEM\CurrentControlSet\Control\DeviceGuard";

    public string CheckId => "CRG-001";
    public string Name => "Credential Guard & LSA Protection";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "CRG-001.1", Title = "Turn On Virtualization Based Security", Expected = "Enabled", WhatItDoes = "Enables VBS, the base for Credential Guard.", Recommendation = "EnableVirtualizationBasedSecurity = 1.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord", Verification = "Get-ItemProperty DeviceGuard → EnableVirtualizationBasedSecurity = 1.", ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard → Turn on VBS", YouAreHere = "Registry Editor (root)", GoTo = "DeviceGuard → EnableVirtualizationBasedSecurity = 1", GraphicalSteps = "1) gpedit → Device Guard → Turn on VBS = Enabled.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity", AlternativeToRegistry = "Prefer gpedit.msc → Device Guard over manual registry editing." },
        new SubCheck { Id = "CRG-001.2", Title = "Select Platform Security Level", Expected = "Secure Boot + DMA Protection", WhatItDoes = "Stronger isolation for VBS.", Recommendation = "RequirePlatformSecurityFeatures = 3.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name RequirePlatformSecurityFeatures -Value 3 -Type DWord", Verification = "RequirePlatformSecurityFeatures = 3.", ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard → Platform Security", YouAreHere = "Registry Editor (root)", GoTo = "DeviceGuard → RequirePlatformSecurityFeatures = 3", GraphicalSteps = "1) Set platform security = Secure Boot + DMA.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures", AlternativeToRegistry = "Prefer gpedit.msc → Device Guard." },
        new SubCheck { Id = "CRG-001.3", Title = "Credential Guard Configuration", Expected = "Enabled with UEFI lock", WhatItDoes = "Protects credentials, locked in firmware.", Recommendation = "LsaCfgFlags = 1.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name LsaCfgFlags -Value 1 -Type DWord", Verification = "LsaCfgFlags = 1.", ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard → Credential Guard", YouAreHere = "Registry Editor (root)", GoTo = "LSA → LsaCfgFlags = 1", GraphicalSteps = "1) Credential Guard = Enabled with UEFI lock.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\LSA\LsaCfgFlags", AlternativeToRegistry = "Prefer gpedit.msc → Device Guard." },
        new SubCheck { Id = "CRG-001.4", Title = "Secure Launch Configuration", Expected = "Enabled", WhatItDoes = "System Guard Secure Launch for boot integrity.", Recommendation = "SystemGuard = 1.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name SystemGuard -Value 1 -Type DWord", Verification = "SystemGuard = 1.", ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard → Secure Launch", YouAreHere = "Registry Editor (root)", GoTo = "DeviceGuard → SystemGuard = 1", GraphicalSteps = "1) Secure Launch = Enabled.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\SystemGuard", AlternativeToRegistry = "Prefer gpedit.msc → Device Guard." },
        new SubCheck { Id = "CRG-001.5", Title = "Run LSASS as protected process (RunAsPPL)", Expected = "Enabled", WhatItDoes = "Blocks Mimikatz-style LSASS reads.", Recommendation = "RunAsPPL = 1.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord", Verification = "RunAsPPL = 1.", ConsoleTool = "regedit.exe", DestinationLabel = "Lsa → RunAsPPL", YouAreHere = "Registry Editor (root)", GoTo = "Control\\Lsa → RunAsPPL = 1", GraphicalSteps = "1) Set RunAsPPL = 1.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL", AlternativeToRegistry = "Registry is the supported method for RunAsPPL." },
        new SubCheck { Id = "CRG-001.6", Title = "Send unencrypted password to 3rd-party SMB", Expected = "Disabled", WhatItDoes = "Reinforces credential protection over SMB.", Recommendation = "EnablePlainTextPassword = 0.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name EnablePlainTextPassword -Value 0 -Type DWord", Verification = "EnablePlainTextPassword = 0.", ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → unencrypted password", YouAreHere = "Registry Editor (root)", GoTo = "LanmanWorkstation → EnablePlainTextPassword = 0", GraphicalSteps = "1) Security Options → disable plaintext.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword", AlternativeToRegistry = "Prefer secpol.msc → Security Options." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var lsa = Registry.LocalMachine.OpenSubKey(LsaPath);
            using var dg = Registry.LocalMachine.OpenSubKey(DgPath);
            var ppl = lsa?.GetValue("RunAsPPL");
            var vbs = dg?.GetValue("EnableVirtualizationBasedSecurity");
            bool ok = (ppl != null && ppl.ToString() == "1") && (vbs != null && vbs.ToString() == "1");
            currentValue = ok ? "Enabled" : "Disabled";
            status = ok ? CheckStatus.Pass : CheckStatus.Fail;
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Enabled", "Use VBS + Credential Guard + LSA protection to stop credential theft.",
            errorMessage: errorMessage,
            description: "Protects NTLM/Kerberos credentials using virtualization-based security.",
            registryPath: $@"HKLM\{LsaPath}\RunAsPPL",
            cisReference: "CIS 5.5",
            riskScore: 80,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{LsaPath}"" /v RunAsPPL",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }
}