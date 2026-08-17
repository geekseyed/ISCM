using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class SmbV1ProtocolCheck : IHardeningCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string ValueName = "SMB1";

    public string CheckId => "SMB-001";
    public string Name => "SMBv1 Protocol";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    // EDIT (گام ۲۶): طبق PDF دو زیرمجموعه (دو جدول) — نه چهارتا
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck
        {
            Id = "SMB-001.1",
            Title = "Disable SMBv1 client/server (Windows Feature)",
            Expected = "Feature removed",
            WhatItDoes = "Removes the SMBv1 feature from the OS.",
            Recommendation = "Remove the legacy SMBv1 feature to eliminate the WannaCry/NotPetya attack surface. A restart is required after removal.",
            CliCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            Verification = "Run: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol → State must be 'Disabled'. Or in OptionalFeatures.exe, 'SMB 1.0/CIFS File Sharing Support' must be unchecked. Restart afterwards.",
            ConsoleTool = "OptionalFeatures.exe",
            DestinationLabel = "Windows Features → SMB 1.0/CIFS Support",
            YouAreHere = "OptionalFeatures window (Turn Windows features on or off)",
            GoTo = "SMB 1.0/CIFS File Sharing Support → uncheck → OK → Restart",
            GraphicalSteps = "1) Scroll to 'SMB 1.0/CIFS File Sharing Support'. 2) Uncheck it. 3) Click OK. 4) Restart the PC.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
            AlternativeToRegistry = "Do not edit the registry by hand. Use the PowerShell prompt above (recommended) or the Windows Features graphical path."
        },
        new SubCheck
        {
            Id = "SMB-001.2",
            Title = "SMB1 server, insecure guest logons & SMB signing",
            Expected = "SMB1=0 · Guest logons=Disabled · Signing=Enabled",
            WhatItDoes = "Disables SMBv1 server, blocks unauthenticated guest access and enforces signed SMB sessions to prevent relay attacks.",
            Recommendation = "Apply the three network-hardening values with one PowerShell prompt instead of manual registry editing.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord",
            Verification = "Run: Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' → SMB1=0 and RequireSecuritySignature=1; and '...\\LanmanWorkstation\\Parameters' → AllowInsecureGuestAuth=0 and RequireSecuritySignature=1.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Lanman Workstation → Insecure guest logons",
            YouAreHere = "Local Group Policy Editor (root)",
            GoTo = "Computer Configuration → Administrative Templates → Network → Lanman Workstation → Enable insecure guest logons → Disabled",
            GraphicalSteps = "1) Expand Computer Configuration → Administrative Templates → Network → Lanman Workstation. 2) Open 'Enable insecure guest logons'. 3) Set Disabled. 4) Then set SMB signing under Security Options.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth",
            AlternativeToRegistry = "Registry editing is not recommended. Run the PowerShell prompt above, or follow the gpedit.msc navigation guide."
        }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);

            if (key != null)
            {
                var registryValue = key.GetValue(ValueName);
                if (registryValue != null && registryValue.ToString() == "0")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Registry Key Missing (Might be Enabled)";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Disabled",
            "Disable SMBv1 protocol via PowerShell or Group Policy to prevent vulnerabilities like EternalBlue.",
            errorMessage: errorMessage,
            description: "SMBv1 is an outdated protocol with known vulnerabilities including EternalBlue (MS17-010).",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 18.3.2",
            riskScore: 90,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe", "OptionalFeatures.exe" },
            subChecks: SubChecks));
    }
}