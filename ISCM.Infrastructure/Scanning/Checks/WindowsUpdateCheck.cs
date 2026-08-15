using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class WindowsUpdateCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    private const string ValueName = "NoAutoUpdate";

    public string CheckId => "WUP-001";
    public string Name => "Windows Update";
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
                var val = key.GetValue(ValueName);
                if (val != null && val.ToString() == "1")
                {
                    currentValue = "Disabled (Manual)";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Automatic";
                    status = CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Not Configured";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Disabled (Manual)",
            recommendation: "Disable automatic updates to prevent untested patches in OT environments.",
            errorMessage: errorMessage,
            description: "In industrial OT environments, automatic updates should be disabled to prevent untested patches from causing system disruption.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "OT-EXCEPTION (No CIS)",
            riskScore: 35,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" }
        ));
    }
}