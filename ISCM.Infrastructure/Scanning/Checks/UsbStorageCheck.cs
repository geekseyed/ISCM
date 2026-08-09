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

public class UsbStorageCheck : IHardeningCheck
{
    public string CheckId => "USB-001";
    public string Name => "USB Storage Policy";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR");
            if (key != null)
            {
                var val = key.GetValue("Start");
                // مقدار 3 یعنی دسترسی مجاز (Fail برای ما)، مقدار 4 یعنی مسدود (Pass برای ما)
                if (val != null && val.ToString() == "4")
                {
                    currentValue = "Restricted";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Allowed";
                    status = CheckStatus.Fail;
                }
            }
            else { currentValue = "Registry Key Missing"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(CheckId, Name, Category, Severity, status, currentValue, "Restricted", "Restrict USB storage devices to prevent malware spread.", errorMessage));
    }
}