using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class WindowsDefenderCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    private const string ValueName = "DisableRealtimeMonitoring";

    public string CheckId => "DEF-001";
    public string Name => "Windows Defender";
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
                var registryValue = key.GetValue(ValueName);
                if (registryValue != null && registryValue.ToString() == "1")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Pass;
                }
            }
            else
            {
                currentValue = "Registry Key Missing";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Enabled",
            recommendation: "Enable Windows Defender real-time protection.",
            errorMessage: errorMessage,
            description: "Windows Defender real-time protection must be enabled to detect and block malware in real time.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 1.2",
            riskScore: 88,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe" }
        ));
    }
}