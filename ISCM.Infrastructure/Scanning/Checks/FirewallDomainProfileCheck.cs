using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class FirewallDomainProfileCheck : IHardeningCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
    private const string ValueName = "EnableFirewall";

    public string CheckId => "FW-001";
    public string Name => "Firewall Domain Profile";
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
                if (registryValue != null)
                {
                    bool isEnabled = registryValue.ToString() == "1";
                    currentValue = isEnabled ? "Enabled" : "Disabled";
                    status = isEnabled ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Not Configured";
                    status = CheckStatus.Warning;
                }
            }
            else
            {
                currentValue = "Registry Key Missing";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        // EDIT (مرحله د): تغذیه متادیتای واقعی
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Enabled",
            recommendation: "Ensure Windows Firewall is enabled for the Domain profile via Group Policy or Control Panel.",
            errorMessage: errorMessage,
            description: "Windows Firewall for Domain profile must be enabled to prevent unauthorized inbound network connections.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 9.1.1",
            riskScore: 75,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe", "wf.msc" }
        ));
    }
}