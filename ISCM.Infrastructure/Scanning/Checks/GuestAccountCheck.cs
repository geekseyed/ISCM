using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ISCM.Infrastructure.Scanning.Checks;

public class GuestAccountCheck : IHardeningCheck, IMultiPathCheck
{
    public string CheckId => "GUEST-001";
    public string Name => "Guest Account";
    public CheckCategory Category => CheckCategory.Account;
    public CheckSeverity Severity => CheckSeverity.Critical;

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
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Guest account status > Disabled",
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
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Rename guest account",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Rename guest account > Set to a unique complex name",
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

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: net user Guest (CMD)
        try
        {
            string output = Run("net", "user Guest");
            var activeLine = output.Split('\n').FirstOrDefault(l => l.Contains("Account active", StringComparison.OrdinalIgnoreCase));
            if (activeLine != null)
            {
                var passed = activeLine.Contains("No", StringComparison.OrdinalIgnoreCase);
                results.Add(new TestResult("Primary", "net user", passed, activeLine.Trim()));
            }
            else
            {
                results.Add(new TestResult("Primary", "net user", false, "Account active line not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "net user", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: PowerShell Get-LocalUser
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-LocalUser -Name 'Guest' | Select-Object -ExpandProperty Enabled\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase);
            results.Add(new TestResult("Cross-check", "Get-LocalUser", passed, $"Enabled = {output.Trim()}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-LocalUser", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: NetUserGetInfo (Win32 API) - همان روش اصلی EvaluateAsync
        try
        {
            IntPtr bufPtr;
            uint result = NetUserGetInfo(null, "Guest", 1, out bufPtr);

            if (result == NERR_Success)
            {
                USER_INFO_1 userInfo = Marshal.PtrToStructure<USER_INFO_1>(bufPtr);
                bool isDisabled = (userInfo.usri1_flags & UF_ACCOUNTDISABLE) != 0;
                NetApiBufferFree(bufPtr);
                results.Add(new TestResult("Verification", "NetUserGetInfo API", isDisabled, isDisabled ? "UF_ACCOUNTDISABLE flag set" : "Account enabled"));
            }
            else
            {
                results.Add(new TestResult("Verification", "NetUserGetInfo API", false, $"API error code: {result}"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "NetUserGetInfo API", false, $"Error: {ex.Message}"));
        }

        return results;
    }

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return o;
        }
        catch { return ""; }
    }
}