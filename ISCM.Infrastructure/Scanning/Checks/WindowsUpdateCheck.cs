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

public class WindowsUpdateCheck : IHardeningCheck
{
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
            // در محیط‌های ایزوله صنعتی، آپدیت خودکار باید خاموش باشد (NoAutoUpdate = 1)
            if (key != null)
            {
                var val = key.GetValue("NoAutoUpdate");
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
                // اگر کلید نبود، یعنی استاندارد نیست
                currentValue = "Not Configured";
                status = CheckStatus.Warning;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Disabled (Manual)", "Disable automatic updates to prevent untested patches in OT environments.", errorMessage));
    }
}}
