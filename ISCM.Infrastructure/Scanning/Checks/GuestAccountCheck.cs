using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SAM\SAM\Domains\Account\Users\000001F5");
            if (key != null)
            {
                var val = key.GetValue("F");
                if (val is byte[] bytes && bytes.Length > 56)
                {
                    // بایت ۵۶ وضعیت فعال/غیرفعال بودن اکانت Guest را نشان می‌دهد
                    currentValue = (bytes[56] & 0x01) == 0 ? "Disabled" : "Enabled";
                    status = currentValue == "Disabled" ? CheckStatus.Pass : CheckStatus.Fail;
                }
            }
            else
            {
                currentValue = "Access Denied or Missing";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Disabled", "Disable the built-in Guest account.", errorMessage));
    }
}
