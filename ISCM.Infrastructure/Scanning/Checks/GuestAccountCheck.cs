using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.DirectoryServices.AccountManagement;
using System.Diagnostics;
using System.DirectoryServices;
using System.Runtime.InteropServices;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

    // --- تعریف P/Invoke برای صحبت مستقیم با هسته ویندوز ---

    // ساختار داده‌ای که ویندوز برمی‌گرداند
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

    // وارد کردن تابع خواندن کاربر از کتابخانه اصلی ویندوز
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserGetInfo(string servername, string username, uint level, out IntPtr bufptr);

    // تابع آزاد کردن حافظه
    [DllImport("Netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr Buffer);

    private const uint UF_ACCOUNTDISABLE = 0x0002; // فلگ غیرفعال بودن حساب در ویندوز
    private const uint NERR_Success = 0; // کد موفقیت

    // -------------------------------------------------------

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            IntPtr bufPtr;
            // صدا زدن مستقیم API ویندوز برای گرفتن اطلاعات Guest (Level 1)
            uint result = NetUserGetInfo(null, "Guest", 1, out bufPtr);

            if (result == NERR_Success)
            {
                // تبدیل حافظه غیرمدیریت شده به ساختار سی‌شارپ ما
                USER_INFO_1 userInfo = Marshal.PtrToStructure<USER_INFO_1>(bufPtr);

                // بررسی فلگ غیرفعال بودن (Bitwise AND)
                bool isDisabled = (userInfo.usri1_flags & UF_ACCOUNTDISABLE) != 0;

                currentValue = isDisabled ? "Disabled" : "Enabled";
                status = isDisabled ? CheckStatus.Pass : CheckStatus.Fail;

                NetApiBufferFree(bufPtr); // آزاد کردن حافظه ویندوز
            }
            else
            {
                currentValue = "API Error Code: " + result;
                status = CheckStatus.Warning;
                errorMessage = "NetUserGetInfo failed with code: " + result;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
            currentValue = $"Exception: {ex.GetType().Name}";
        }

        return Task.FromResult(new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Disabled",
            "Disable the built-in Guest account via Local Security Policy or net command.",
            errorMessage
        ));
    }
}