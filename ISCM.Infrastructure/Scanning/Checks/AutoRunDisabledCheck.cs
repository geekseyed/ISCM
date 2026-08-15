using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AutoRunDisabledCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string ValueName = "NoDriveTypeAutoRun";

    public string CheckId => "ARD-001";
    public string Name => "AutoRun Disabled";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.Medium;

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
                if (registryValue != null && registryValue.ToString() == "255")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Enabled or Partially Enabled";
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

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Disabled",
            recommendation: "Disable AutoRun for all drives via Group Policy to prevent malware spreading via USB.",
            errorMessage: errorMessage,
            description: "AutoRun must be disabled for all drive types to prevent malware execution from USB drives and CDs.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 18.8.3.1",
            riskScore: 65,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" }
        ));
    }
}