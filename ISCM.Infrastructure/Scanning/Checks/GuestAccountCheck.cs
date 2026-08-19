using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

    // Paths verified against the Revised PDF (item 3): both under Local Policies > Security Options.
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "GUEST-001.1", Title = "Accounts: Guest account status", Expected = "Disabled",
            WhatItDoes = "Turns off the built-in Guest account entirely.",
            Recommendation = "Disable the built-in Guest account.",
            CheckCurrentCli = "net user Guest", CliCommand = "net user Guest /active:no",
            VerifyCli = "net user Guest", Verification = "'Account active' shows No.",
            ValueMap = "/active:no = Disabled.", CliTokens = "Guest: built-in account; /active:no disables it.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → Guest account status",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Guest account status",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Guest account status' > Disabled",
            GraphicalSteps = "1) secpol.msc. 2) Expand Local Policies. 3) Click Security Options. 4) Right pane: double-click 'Accounts: Guest account status'. 5) Disabled.",
            UndoCli = "net user Guest /active:yes", IgnoreConsequence = "Anonymous guest access remains an attack vector.",
            HasRegistryPath = false, RegistryPath = "", AlternativeToRegistry = "" },
        new SubCheck { Id = "GUEST-001.2", Title = "Accounts: Rename guest account", Expected = "Unique complex name",
            WhatItDoes = "Renames Guest so attackers cannot target a known account name.",
            Recommendation = "Rename the SID -501 account.",
            CheckCurrentCli = "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select Name",
            CliCommand = "$g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; Rename-LocalUser -SID $g.SID -NewName 'Seyedi.pro'",
            VerifyCli = "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select Name",
            Verification = "Name is not 'Guest'.", ValueMap = "", CliTokens = "SID -501: built-in guest; Rename-LocalUser changes its name.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → Rename guest account",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Rename guest account' > Set to a unique complex name",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Rename guest account",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies",
            GraphicalSteps = "1) secpol.msc → Local Policies → Security Options. 2) Double-click 'Accounts: Rename guest account'. 3) Enter a unique complex name.",
            UndoCli = "# rename back if required", IgnoreConsequence = "Known account name stays targetable.",
            HasRegistryPath = false, RegistryPath = "", AlternativeToRegistry = "" }
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
            CheckId, Name, Category, Severity, status, currentValue,
            "Disabled",
            "Disable the built-in Guest account via Local Security Policy or net command.",
            errorMessage: errorMessage,
            description: "The built-in Guest account provides anonymous access and must be disabled.",
            registryPath: null,
            cisReference: "CIS 2.3.1.1",
            riskScore: 95,
            sourceType: "NetUserGetInfo (Netapi32)",
            sourceCommand: "net user Guest",
            fixTools: new List<string> { "net.exe", "lusrmgr.msc" },
            subChecks: SubChecks));
    }
}