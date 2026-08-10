using System.Management;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Infrastructure.Scanning.Checks;

public class AdminAccountCountCheck : IHardeningCheck
{
    public string CheckId => "ADM-001";
    public string Name => "Admin Account Count";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.High;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            // استفاده از WMI برای شمارش اعضای گروه Administrators
            string machineName = Environment.MachineName;
            string query = $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"";

            using var searcher = new ManagementObjectSearcher(query);
            int adminCount = searcher.Get().Count;

            currentValue = $"{adminCount} Admins";
            // استاندارد ما: کمتر یا مساوی ۲ ادمین
            status = adminCount <= 2 ? CheckStatus.Pass : CheckStatus.Fail;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        return Task.FromResult(new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "<= 2 Admins",
            "Limit local administrator group to essential members only.",
            errorMessage
        ));
    }
}