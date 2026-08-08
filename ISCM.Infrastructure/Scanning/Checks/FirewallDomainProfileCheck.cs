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

public class FirewallDomainProfileCheck : IHardeningCheck
{
    public string CheckId => "FW-001";
    public string Name => "Firewall Domain Profile";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            // مسیر رجیستری ویندوز برای وضعیت فایروال دامنه
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");

            if (key != null)
            {
                var registryValue = key.GetValue("EnableFirewall");
                if (registryValue != null)
                {
                    // در رجیستری، 1 یعنی روشن، 0 یعنی خاموش
                    bool isEnabled = registryValue.ToString() == "1";
                    currentValue = isEnabled ? "Enabled" : "Disabled";

                    // مقایسه با استاندارد ما (باید روشن باشد)
                    status = isEnabled ? CheckStatus.Pass : CheckStatus.Fail;
                }
                else
                {
                    currentValue = "Not Configured";
                    status = CheckStatus.Warning;
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
            // اگر دسترسی به رجیستیر مردود بود
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        // ساخت آبجکت نتیجه
        var finding = new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Enabled", // Expected Value
            "Ensure Windows Firewall is enabled for the Domain profile via Group Policy or Control Panel.",
            errorMessage
        );

        return Task.FromResult(finding);
    }
}
