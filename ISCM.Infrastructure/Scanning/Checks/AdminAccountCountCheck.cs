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
            string machineName = Environment.MachineName;
            string query = $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"";

            using var searcher = new ManagementObjectSearcher(query);
            int adminCount = searcher.Get().Count;

            currentValue = $"{adminCount} Admins";
            status = adminCount <= 2 ? CheckStatus.Pass : CheckStatus.Fail;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
        }

        // EDIT (مرحله د): تغذیه متادیتای واقعی
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "<= 2 Admins",
            recommendation: "Limit local administrator group to essential members only.",
            errorMessage: errorMessage,
            description: "Limiting local administrators reduces the attack surface for privilege escalation. Excessive admin accounts increase the risk of credential theft.",
            registryPath: null,
            cisReference: "CIS 2.3.1.5",
            riskScore: 20,
            sourceType: "WMI (Win32_GroupUser)",
            sourceCommand: "net localgroup Administrators",
            fixTools: new List<string> { "powershell.exe", "compmgmt.msc" }
        ));
    }
}