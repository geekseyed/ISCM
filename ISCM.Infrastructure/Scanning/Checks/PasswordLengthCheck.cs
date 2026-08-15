using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class PasswordLengthCheck : IHardeningCheck
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string ValueName = "MinimumPasswordLength";

    public string CheckId => "PWD-001";
    public string Name => "Min Password Length";
    public CheckCategory Category => CheckCategory.Account;
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
                if (val != null && int.TryParse(val.ToString(), out int length))
                {
                    currentValue = $"{length} chars";
                    status = length >= 14 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Not Configured (0)";
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

        // EDIT (مرحله د): تغذیه متادیتای واقعی مطابق طرح
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "14 chars",
            recommendation: "Set minimum password length to 14 characters via Local Security Policy.",
            errorMessage: errorMessage,
            description: "Minimum password length policy defines the minimum number of characters required for user passwords. Short passwords are vulnerable to brute-force and dictionary attacks.",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 5.2.3",
            riskScore: 60,
            sourceType: "secedit",
            sourceCommand: "secedit /export /cfg output.txt /areas SECURITYPOLICY",
            fixTools: new List<string> { "secpol.msc" }
        ));
    }
}