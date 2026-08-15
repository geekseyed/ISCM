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
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Disabled",
            recommendation: "Disable SMBv1 protocol via PowerShell or Group Policy to prevent vulnerabilities like EternalBlue.",
            errorMessage: errorMessage,
            description: "SMBv1 is an outdated protocol with critical vulnerabilities (e.g., EternalBlue/WannaCry) and must be disabled.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 18.3.2",
            riskScore: 90,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe", "OptionalFeatures.exe" }
        ));
    }
}