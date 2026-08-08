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

public class SmbV1ProtocolCheck : IHardeningCheck
{
    public string CheckId => "SMB-001";
    public string Name => "SMBv1 Protocol";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            // مسیر رجیستری برای SMBv1
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");

            if (key != null)
            {
                var registryValue = key.GetValue("SMB1");
                // اگر مقدار 0 باشد یعنی غیرفعال است (Pass). اگر 1 یا خالی باشد یعنی فعال است (Fail)
                if (registryValue != null && registryValue.ToString() == "0")
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
            else
            {
                currentValue = "Registry Key Missing (Might be Enabled)";
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
            "Disable SMBv1 protocol via PowerShell or Group Policy to prevent vulnerabilities like EternalBlue.",
            errorMessage
        );

        return Task.FromResult(finding);
    }
}
