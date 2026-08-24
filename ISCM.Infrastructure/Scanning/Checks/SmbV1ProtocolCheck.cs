using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class SmbV1ProtocolCheck : IHardeningCheck, IMultiPathCheck
{
    private const string LanmanServerPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string LanmanWorkstationPath = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

    public string CheckId => "SMB-001";
    public string Name => "Disable SMBv1";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.Critical;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "SMB-001.1", Title = "Remove SMBv1 Windows feature (PowerShell / DISM)", Expected = "Feature removed (State Disabled)",
            WhatItDoes = "Removes the SMBv1 optional feature exploited by WannaCry/NotPetya.", Recommendation = "Run elevated PowerShell on endpoint/image; restart after.",
            CheckCurrentCli = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select State", CliCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            VerifyCli = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select State", Verification = "State = Disabled. Restart required.",
            ValueMap = "State Disabled = removed, Enabled = present.", CliTokens = "-Online: target running OS; -FeatureName SMB1Protocol: the SMB1 optional feature; -NoRestart: defer reboot.",
            ConsoleTool = "OptionalFeatures.exe", DestinationLabel = "Windows Features → SMB 1.0/CIFS File Sharing Support",
            GraphicalPathFull = "Not a native Administrative Template policy — use elevated PowerShell/DISM, or Control Panel > Programs > Turn Windows features on or off > SMB 1.0/CIFS File Sharing Support (uncheck)",
            ConsolePath = "Control Panel > Programs > Turn Windows features on or off",
            YouAreHere = "Desktop / elevated PowerShell", GoTo = "Elevated PowerShell > 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' > Restart required",
            GraphicalSteps = "1) OptionalFeatures.exe (or PowerShell). 2) Locate 'SMB 1.0/CIFS File Sharing Support'. 3) Uncheck. 4) OK. 5) Restart.",
            UndoCli = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart", IgnoreConsequence = "WannaCry/NotPetya-class ransomware vector remains open.", HasRegistryPath = false },
        new SubCheck { Id = "SMB-001.2", Title = "SMB1 server registry (LanmanServer SMB1 = 0)", Expected = "0",
            WhatItDoes = "Disables SMBv1 on the server side.", Recommendation = "SMB1 = 0.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select SMB1",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 0 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select SMB1",
            Verification = "SMB1 = 0.", ValueMap = "0 = off, 1 = on.",
            CliTokens = "LanmanServer SMB1: server-side disable.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Lanman Server → SMB1",
            GraphicalPathFull = "Computer Configuration > Preferences > Windows Settings > Registry > HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters > SMB1 = 0",
            ConsolePath = "Computer Configuration > Preferences > Windows Settings > Registry",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Preferences > Windows Settings > Registry > HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters > SMB1 = 0",
            GraphicalSteps = "1) gpedit → Preferences → Windows Settings → Registry. 2) New Registry Item. 3) Hive HKLM. 4) Key Path SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters. 5) Value name SMB1. 6) Value data 0.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 1",
            IgnoreConsequence = "SMBv1 server remains enabled.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
            AlternativeToRegistry = "Prefer PowerShell/DISM feature removal over registry hacks." },
        new SubCheck { Id = "SMB-001.3", Title = "Allow insecure guest logons (Lanman Workstation)", Expected = "Disabled",
            WhatItDoes = "Blocks unauthenticated SMB guest access.", Recommendation = "AllowInsecureGuestAuth = 0.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' | Select AllowInsecureGuestAuth",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' | Select AllowInsecureGuestAuth",
            Verification = "AllowInsecureGuestAuth = 0.", ValueMap = "0 = block, 1 = allow.",
            CliTokens = "LanmanWorkstation AllowInsecureGuestAuth: block guest.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons",
            ConsolePath = "Computer Configuration > Administrative Templates > Network > Lanman Workstation",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Network > Lanman Workstation > 'Allow insecure guest logons' > Disabled",
            GraphicalSteps = "1) gpedit → Administrative Templates → Network → Lanman Workstation. 2) 'Enable insecure guest logons' = Disabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 1",
            IgnoreConsequence = "Guest access attacks remain possible.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth",
            AlternativeToRegistry = "Prefer gpedit.msc (Lanman Workstation) over manual registry editing." },
        new SubCheck { Id = "SMB-001.4", Title = "Microsoft network client: Digitally sign communications (always)", Expected = "Enabled",
            WhatItDoes = "Requires SMB client signing.", Recommendation = "RequireSecuritySignature = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' | Select RequireSecuritySignature",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' | Select RequireSecuritySignature",
            Verification = "RequireSecuritySignature = 1.", ValueMap = "1 = require.",
            CliTokens = "LanmanWorkstation RequireSecuritySignature: signing.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → Microsoft network client: Digitally sign communications (always)",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Digitally sign communications (always)",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Digitally sign communications (always) > Enabled",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Microsoft network client: Digitally sign communications (always)' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name RequireSecuritySignature -Value 0",
            IgnoreConsequence = "SMB client signing not enforced.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature",
            AlternativeToRegistry = "Prefer secpol.msc (Security Options) over manual registry editing." },
        new SubCheck { Id = "SMB-001.5", Title = "Microsoft network server: Digitally sign communications (always)", Expected = "Enabled",
            WhatItDoes = "Requires SMB server signing.", Recommendation = "RequireSecuritySignature = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select RequireSecuritySignature",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select RequireSecuritySignature",
            Verification = "RequireSecuritySignature = 1.", ValueMap = "1 = require.",
            CliTokens = "LanmanServer RequireSecuritySignature: signing.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options → Microsoft network server: Digitally sign communications (always)",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always)",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc → Security Settings → Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always) > Enabled",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Microsoft network server: Digitally sign communications (always)' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -Value 0",
            IgnoreConsequence = "SMB server signing not enforced.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature",
            AlternativeToRegistry = "Prefer secpol.msc (Security Options) over manual registry editing." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // 1. SMB1 server registry (LanmanServer SMB1 = 0)
            using var serverKey = Registry.LocalMachine.OpenSubKey(LanmanServerPath);
            var smb1Val = serverKey?.GetValue("SMB1");
            if (smb1Val != null && smb1Val.ToString() == "0") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. AllowInsecureGuestAuth (LanmanWorkstation = 0)
            using var workstationKey = Registry.LocalMachine.OpenSubKey(LanmanWorkstationPath);
            var guestVal = workstationKey?.GetValue("AllowInsecureGuestAuth");
            if (guestVal != null && guestVal.ToString() == "0") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 3. Client signing (LanmanWorkstation RequireSecuritySignature = 1)
            var clientSignVal = workstationKey?.GetValue("RequireSecuritySignature");
            if (clientSignVal != null && clientSignVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 4. Server signing (LanmanServer RequireSecuritySignature = 1)
            var serverSignVal = serverKey?.GetValue("RequireSecuritySignature");
            if (serverSignVal != null && serverSignVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 5. Check if SMB1 feature is disabled via PowerShell
            string featureOutput = Run("powershell.exe", "-Command \"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State\"");
            if (featureOutput.Contains("Disabled", StringComparison.OrdinalIgnoreCase)) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} SMB settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "SMBv1 disabled + signing enforced",
                "Disable SMBv1 protocol and enforce SMB signing to prevent vulnerabilities like EternalBlue.",
                errorMessage: string.Empty,
                description: "SMBv1 is an outdated protocol with known vulnerabilities including EternalBlue (MS17-010).",
                registryPath: $@"HKLM\{LanmanServerPath}\SMB1",
                cisReference: "CIS 18.3.2", riskScore: 90, sourceType: "RegistryReader + PowerShell",
                sourceCommand: $@"reg query ""HKLM\{LanmanServerPath}"" /v SMB1",
                fixTools: new List<string> { "powershell.exe", "OptionalFeatures.exe", "gpedit.msc", "secpol.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "SMBv1 is an outdated protocol with known vulnerabilities including EternalBlue (MS17-010).",
                registryPath: $@"HKLM\{LanmanServerPath}\SMB1",
                cisReference: "CIS 18.3.2", riskScore: 90, sourceType: "RegistryReader + PowerShell",
                sourceCommand: $@"reg query ""HKLM\{LanmanServerPath}"" /v SMB1",
                fixTools: new List<string> { "powershell.exe", "OptionalFeatures.exe", "gpedit.msc", "secpol.msc" },
                subChecks: SubChecks));
        }
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry برای SMB1
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LanmanServerPath);
            if (key != null)
            {
                var v = key.GetValue("SMB1");
                if (v != null && v.ToString() == "0")
                {
                    results.Add(new TestResult("Primary", "Registry (SMB1)", true, "SMB1 = 0 (Disabled)"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (SMB1)", false, $"SMB1 = {v}"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (SMB1)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (SMB1)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: PowerShell Get-SmbServerConfiguration
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                var passed = output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase);
                results.Add(new TestResult("Cross-check", "Get-SmbServerConfiguration", passed, passed ? "EnableSMB1Protocol = False" : $"EnableSMB1Protocol = {output.Trim()}"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-SmbServerConfiguration", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: Get-WindowsOptionalFeature
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                var passed = output.Trim().Equals("Disabled", StringComparison.OrdinalIgnoreCase);
                results.Add(new TestResult("Verification", "Get-WindowsOptionalFeature", passed, passed ? "State = Disabled" : $"State = {output.Trim()}"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Get-WindowsOptionalFeature", false, $"Error: {ex.Message}"));
        }
        return results;
    }

    private static CheckStatus GetWorstStatus(IEnumerable<CheckStatus> statuses)
    {
        if (statuses.Any(s => s == CheckStatus.Fail)) return CheckStatus.Fail;
        if (statuses.Any(s => s == CheckStatus.Error)) return CheckStatus.Error;
        if (statuses.Any(s => s == CheckStatus.Unknown)) return CheckStatus.Unknown;
        return CheckStatus.Pass;
    }

    private static string Run(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            if (p == null) return string.Empty;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return o;
        }
        catch { return string.Empty; }
    }
}