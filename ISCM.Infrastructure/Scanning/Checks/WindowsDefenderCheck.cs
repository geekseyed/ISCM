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

public class WindowsDefenderCheck : IHardeningCheck
{
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            if (key != null)
            {
                var registryValue = key.GetValue("DisableRealtimeMonitoring");
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

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Enabled", "Enable Windows Defender real-time protection.", errorMessage));
    }
}