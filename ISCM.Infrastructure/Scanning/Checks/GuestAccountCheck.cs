using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public string usri1_home_dir;
        public string usri1_comment;
        public uint usri1_flags;
        public string usri1_script_path;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserGetInfo(string servername, string username, uint level, out IntPtr bufptr);

    [DllImport("Netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr Buffer);

    private const uint UF_ACCOUNTDISABLE = 0x0002;
    private const uint NERR_Success = 0;

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            IntPtr bufPtr;
            uint result = NetUserGetInfo(null, "Guest", 1, out bufPtr);

            if (result == NERR_Success)
            {
                USER_INFO_1 userInfo = Marshal.PtrToStructure<USER_INFO_1>(bufPtr);
                bool isDisabled = (userInfo.usri1_flags & UF_ACCOUNTDISABLE) != 0;

                currentValue = isDisabled ? "Disabled" : "Enabled";
                status = isDisabled ? CheckStatus.Pass : CheckStatus.Fail;

                NetApiBufferFree(bufPtr);
            }
            else
            {
                currentValue = "Requires Admin Rights";
                status = CheckStatus.Ignored;
                errorMessage = "NetUserGetInfo failed with code: " + result;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
            currentValue = $"Exception: {ex.GetType().Name}";
        }

        // EDIT (مرحله د): تغذیه متادیتای واقعی
        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            expectedValue: "Disabled",
            recommendation: "Disable the built-in Guest account via Local Security Policy or net command.",
            errorMessage: errorMessage,
            description: "The built-in Guest account provides anonymous access to the system and must always be disabled to prevent unauthorized access.",
            registryPath: null,
            cisReference: "CIS 2.3.1.1",
            riskScore: 95,
            sourceType: "NetUserGetInfo (Netapi32)",
            sourceCommand: "net user Guest",
            fixTools: new List<string> { "net.exe", "lusrmgr.msc" }
        ));
    }
}