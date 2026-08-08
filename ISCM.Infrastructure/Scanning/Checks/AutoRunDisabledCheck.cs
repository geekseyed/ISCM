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

public class AutoRunDisabledCheck : IHardeningCheck
{
    public string CheckId => "ARD-001";
    public string Name => "AutoRun Disabled";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.Medium;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            // مسیر رجیستری برای غیرفعال کردن AutoRun روی تمام درایوها
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");

            if (key != null)
            {
                var registryValue = key.GetValue("NoDriveTypeAutoRun");
                // مقدار 255 (باینری) یعنی همه درایوها بسته شده اند
                if (registryValue != null && registryValue.ToString() == "255")
                {
                    currentValue = "Disabled";
                    status = CheckStatus.Pass;
                }
                else
                {
                    currentValue = "Enabled or Partially Enabled";
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

        var finding = new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Disabled", // Expected Value
            "Disable AutoRun for all drives via Group Policy to prevent malware spreading via USB.",
            errorMessage
        );

        return Task.FromResult(finding);
    }
}
