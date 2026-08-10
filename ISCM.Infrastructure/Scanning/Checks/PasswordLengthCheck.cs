using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class PasswordLengthCheck : IHardeningCheck
{
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
            // مسیر رجیستری برای سیاست‌های رمز عبور (اگر با GPO تنظیم شده باشد)
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                var val = key.GetValue("MinimumPasswordLength");
                if (val != null && int.TryParse(val.ToString(), out int length))
                {
                    currentValue = $"{length} chars";
                    status = length >= 14 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Not Configured (0)";
                    status = CheckStatus.Fail; // اگر تنظیم نشده باشد، یعنی امن نیست
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
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "14 chars",
            "Set minimum password length to 14 characters via Local Security Policy.",
            errorMessage
        ));
    }
}