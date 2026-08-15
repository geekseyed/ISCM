using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class UsbStorageCheck : IHardeningCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string ValueName = "Start";

    public string CheckId => "USB-001";
    public string Name => "USB Storage Policy";
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
                if (val != null && val.ToString() == "4")
                {
                    currentValue = "Restricted";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Allowed";
                    status = CheckStatus.Fail;
                }
            }
            else { currentValue = "Registry Key Missing"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Restricted",
            recommendation: "Restrict USB storage devices to prevent malware spread.",
            errorMessage: errorMessage,
            description: "USB storage must be restricted to prevent data exfiltration and malware introduction via removable media.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 10.2",
            riskScore: 80,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "regedit.exe", "gpedit.msc" }
        ));
    }
}