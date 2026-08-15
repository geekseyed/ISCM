using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class LmCompatibilityCheck : IHardeningCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string ValueName = "LmCompatibilityLevel";

    public string CheckId => "LM-001";
    public string Name => "LM Hash Compatibility";
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
                if (val != null && int.TryParse(val.ToString(), out int level))
                {
                    currentValue = $"Level {level}";
                    status = level >= 5 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Not Configured (Default)";
                    status = CheckStatus.Fail;
                }
            }
            else { currentValue = "Registry Key Missing"; status = CheckStatus.Warning; }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Level 5 (NTLMv2 Only)",
            recommendation: "Set LAN Manager authentication level to 5 to reject insecure LM/NTLM hashes.",
            errorMessage: errorMessage,
            description: "LAN Manager authentication must be set to NTLMv2 only (level 5) to prevent pass-the-hash attacks using insecure LM/NTLM hashes.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 2.3.10.2",
            riskScore: 75,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "secpol.msc" }
        ));
    }
}