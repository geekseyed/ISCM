using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AutoLogonCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string ValueName = "AutoAdminLogon";

    public string CheckId => "ALG-001";
    public string Name => "AutoLogon Disabled";
    public CheckCategory Category => CheckCategory.System;
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
                if (val != null && val.ToString() == "0")
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
            expectedValue: "Disabled",
            recommendation: "Disable AutoLogon to require credential entry upon boot.",
            errorMessage: errorMessage,
            description: "AutoLogon stores credentials in plaintext in the registry and enables unauthorized system access without authentication.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 2.3.11.1",
            riskScore: 40,
            sourceType: "RegistryReader",
            sourceCommand: $"reg query \"HKLM\\{RegistryPath}\" /v {ValueName}",
            fixTools: new List<string> { "regedit.exe" }
        ));
    }
}