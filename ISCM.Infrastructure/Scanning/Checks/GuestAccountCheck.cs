using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Runtime.InteropServices;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

    // EDIT (گام ۲۶): دو زیرمجموعه با راهنمای کامل (توصیه → پرامپت → verifikasi → ناوبری)
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck
        {
            Id = "GUEST-001.1",
            Title = "Accounts: Guest account status",
            Expected = "Disabled",
            WhatItDoes = "Turns off the built-in Guest account entirely.",
            Recommendation = "Disable the built-in Guest account to remove the anonymous-access attack vector.",
            CliCommand = "net user Guest /active:no",
            Verification = "Run: net user Guest → 'Account active' must show 'No'. Or in secpol.msc → Security Options → 'Accounts: Guest account status' = Disabled.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Guest account status",
            YouAreHere = "Local Security Policy (root) → Local Policies",
            GoTo = "Security Settings → Local Policies → Security Options → Accounts: Guest account status → Disabled",
            GraphicalSteps = "1) Expand Local Policies. 2) Click Security Options. 3) Double-click 'Accounts: Guest account status'. 4) Set Disabled.",
            HasRegistryPath = false,
            RegistryPath = "",
            AlternativeToRegistry = ""
        },
        new SubCheck
        {
            Id = "GUEST-001.2",
            Title = "Accounts: Rename guest account",
            Expected = "Unique complex name",
            WhatItDoes = "Renames Guest so attackers cannot target a known account name.",
            Recommendation = "Rename Guest to a unique complex name so attackers cannot target a known account.",
            CliCommand = "$g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; Rename-LocalUser -SID $g.SID -NewName 'Seyedi.pro'",
            Verification = "Run: Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } → Name must NOT be 'Guest'.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Rename guest account",
            YouAreHere = "Local Security Policy (root) → Local Policies",
            GoTo = "Security Settings → Local Policies → Security Options → Accounts: Rename guest account → set unique name",
            GraphicalSteps = "1) In Security Options, double-click 'Accounts: Rename guest account'. 2) Enter a unique complex name.",
            HasRegistryPath = false,
            RegistryPath = "",
            AlternativeToRegistry = ""
        }
    };

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

        return Task.FromResult(new Finding(
            CheckId,
            Name,
            Category,
            Severity,
            status,
            currentValue,
            "Disabled",
            "Disable the built-in Guest account via Local Security Policy or net command.",
            errorMessage: errorMessage,
            description: "The built-in Guest account provides anonymous access to the system and must always be disabled to prevent unauthorized access.",
            registryPath: null,
            cisReference: "CIS 2.3.1.1",
            riskScore: 95,
            sourceType: "NetUserGetInfo (Netapi32)",
            sourceCommand: "net user Guest",
            fixTools: new List<string> { "net.exe", "lusrmgr.msc" },
            subChecks: SubChecks));
    }
}