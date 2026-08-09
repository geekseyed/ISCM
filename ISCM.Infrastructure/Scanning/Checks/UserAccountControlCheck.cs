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

public class UacCheck : IHardeningCheck
{
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                var val = key.GetValue("EnableLUA");
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

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Enabled", "Ensure UAC is enabled to prevent unauthorized system changes.", errorMessage));
    }
}