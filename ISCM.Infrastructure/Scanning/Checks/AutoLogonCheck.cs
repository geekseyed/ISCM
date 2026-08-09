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

public class AutoLogonCheck : IHardeningCheck
{
    public string CheckId => "ALG-001";
    public string Name => "AutoLogon Disabled";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key != null)
            {
                var val = key.GetValue("AutoAdminLogon");
                // باید 0 باشد (غیرفعال)
                if (val != null && val.ToString() == "0")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Enabled";
                    status = CheckStatus.Fail;
                }
            }
            else { currentValue = "Registry Key Missing"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Disabled", "Disable AutoLogon to require credential entry upon boot.", errorMessage));
    }
}
