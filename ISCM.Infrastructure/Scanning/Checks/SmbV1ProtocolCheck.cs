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

    // EDIT (گام ۲۶): چهار زیرمجموعهٔ تیتر ۱۳ PDF
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck
        {
            Id = "SMB-001.1",
            Title = "Disable SMBv1 client/server (Windows Feature)",
            Expected = "Feature removed",
            WhatItDoes = "Removes the SMBv1 feature from the OS.",
            ConsolePath = "Control Panel > Programs > Turn Windows features on or off",
            ConsoleTool = "OptionalFeatures.exe",
            DestinationLabel = "Windows Features → SMB 1.0/CIFS Support",
            RegistryPath = null,
            CliCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        },
        new SubCheck
        {
            Id = "SMB-001.2",
            Title = "SMB1 server (registry)",
            Expected = "0",
            WhatItDoes = "Disables SMBv1 on the server side via registry.",
            ConsolePath = "Registry (no GPO console)",
            ConsoleTool = "regedit.exe",
            DestinationLabel = "Registry → LanmanServer\\Parameters → SMB1",
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 0 -Type DWord"
        },
        new SubCheck
        {
            Id = "SMB-001.3",
            Title = "Allow insecure guest logons",
            Expected = "Disabled",
            WhatItDoes = "Blocks unauthenticated guest access over SMB.",
            ConsolePath = "Computer Configuration > Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Lanman Workstation → Insecure guest logons",
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord"
        },
        new SubCheck
        {
            Id = "SMB-001.4",
            Title = "SMB signing (client and server)",
            Expected = "Enabled",
            WhatItDoes = "Ensures only signed SMB sessions, preventing relay attacks.",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Digitally sign communications",
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -Value 1; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name RequireSecuritySignature -Value 1"
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
            subChecks: SubChecks));   // EDIT (گام ۲۶)
    }
}