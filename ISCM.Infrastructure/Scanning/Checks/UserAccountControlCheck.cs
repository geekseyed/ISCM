using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class UacCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string ValueName = "EnableLUA";

    public string CheckId => "UAC-001";
    public string Name => "User Account Control (UAC)";
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
            recommendation: "Ensure UAC is enabled to prevent unauthorized system changes.",
            errorMessage: errorMessage,
            description: "User Account Control prevents unauthorized system changes by prompting for administrator approval.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 2.3.17.1",
            riskScore: 70,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "UserAccountControlSettings.exe" }
        ));
    }
}