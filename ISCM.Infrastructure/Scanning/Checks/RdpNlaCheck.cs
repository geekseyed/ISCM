using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class RdpNlaCheck : IHardeningCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string ValueName = "UserAuthentication";

    public string CheckId => "RDP-001";
    public string Name => "RDP Network Level Authentication";
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
                var val = key.GetValue(ValueName);
                if (val != null && val.ToString() == "1")
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Fail;
                }
            }
            else { currentValue = "Registry Key Missing"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Enabled",
            recommendation: "Enable NLA for RDP to prevent MitM attacks.",
            errorMessage: errorMessage,
            description: "Network Level Authentication for RDP requires authentication before establishing a full session, preventing Man-in-the-Middle attacks.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 18.10.10.1",
            riskScore: 85,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "SystemPropertiesRemote.exe", "powershell.exe" }
        ));
    }
}