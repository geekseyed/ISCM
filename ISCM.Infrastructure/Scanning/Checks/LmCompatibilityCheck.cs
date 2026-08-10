using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class LmCompatibilityCheck : IHardeningCheck
{
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            if (key != null)
            {
                var val = key.GetValue("LmCompatibilityLevel");
                if (val != null && int.TryParse(val.ToString(), out int level))
                {
                    currentValue = $"Level {level}";
                    // Level 5 یعنی فقط NTLMv2 استفاده شود و LM کاملاً رد شود
                    status = level >= 5 ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    // اگر کلید نباشد، ویندوز به صورت پیش‌فرض از سطح پایین‌تری استفاده می‌کند
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
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Level 5 (NTLMv2 Only)",
            "Set LAN Manager authentication level to 5 to reject insecure LM/NTLM hashes.",
            errorMessage
        ));
    }
}