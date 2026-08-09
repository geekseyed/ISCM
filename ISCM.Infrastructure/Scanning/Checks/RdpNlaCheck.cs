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

public class RdpNlaCheck : IHardeningCheck
{
    public string CheckId => "RDP-001";
    public string Name => "RDP Network Level Authentication";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            if (key != null)
            {
                var val = key.GetValue("UserAuthentication");
                // باید 1 باشد (اعتبارسنجی شبکه قبل از لاگین)
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

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Enabled", "Enable NLA for RDP to prevent MitM attacks.", errorMessage));
    }
}
