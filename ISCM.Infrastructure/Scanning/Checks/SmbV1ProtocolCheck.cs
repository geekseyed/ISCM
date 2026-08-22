using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

// EDIT (گروه D - اولویت ۱): پیاده‌سازی IMultiPathCheck برای تست‌های واقعی چندمسیره
public class SmbV1ProtocolCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string ValueName = "SMB1";

    public string CheckId => "SMB-001";
    public string Name => "SMBv1 Protocol";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    // Paths verified against the Revised PDF (item 13): feature removal is NOT a GPO node.
    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "SMB-001.1", Title = "Remove SMBv1 Windows feature (PowerShell / DISM)", Expected = "Feature removed (State Disabled)",
            WhatItDoes = "Removes the SMBv1 optional feature exploited by WannaCry/NotPetya.",
            Recommendation = "Run elevated PowerShell on endpoint/image; restart after.",
            CheckCurrentCli = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select State",
            CliCommand = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            VerifyCli = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select State",
            Verification = "State = Disabled. Restart required.",
            ValueMap = "State Disabled = removed, Enabled = present.",
            CliTokens = "-Online: target running OS; -FeatureName SMB1Protocol: the SMB1 optional feature; -NoRestart: defer reboot.",
            ConsoleTool = "OptionalFeatures.exe", DestinationLabel = "Windows Features → SMB 1.0/CIFS File Sharing Support",
            GraphicalPathFull = "Not a native Administrative Template policy — use elevated PowerShell/DISM, or Control Panel > Programs > Turn Windows features on or off > SMB 1.0/CIFS File Sharing Support (uncheck)",
            ConsolePath = "Control Panel > Programs > Turn Windows features on or off",
            YouAreHere = "Desktop / elevated PowerShell", GoTo = "Elevated PowerShell > 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' > Restart required",
            GraphicalSteps = "1) OptionalFeatures.exe (or PowerShell). 2) Locate 'SMB 1.0/CIFS File Sharing Support'. 3) Uncheck. 4) OK. 5) Restart.",
            UndoCli = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            IgnoreConsequence = "WannaCry/NotPetya-class ransomware vector remains open.",
            HasRegistryPath = false, RegistryPath = "", AlternativeToRegistry = "Prefer PowerShell/DISM feature removal over registry hacks." },
        new SubCheck { Id = "SMB-001.2", Title = "SMB1 server registry + insecure guest logons + SMB signing", Expected = "SMB1=0 · Guest logons Disabled · Signing Enabled",
            WhatItDoes = "Disables SMBv1 server, blocks unauthenticated guest access, enforces signed SMB sessions.",
            Recommendation = "Apply the three separate controls below.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select SMB1,RequireSecuritySignature",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -Value 1; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name RequireSecuritySignature -Value 1",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' | Select SMB1,RequireSecuritySignature",
            Verification = "SMB1=0, AllowInsecureGuestAuth=0, RequireSecuritySignature=1 (server+workstation).",
            ValueMap = "SMB1 0=off; AllowInsecureGuestAuth 0=block; RequireSecuritySignature 1=require.",
            CliTokens = "LanmanServer SMB1: server-side disable; LanmanWorkstation AllowInsecureGuestAuth: block guest; RequireSecuritySignature: signing.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Lanman Workstation → Enable insecure guest logons + Security Options → SMB signing",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons (Disabled); SMB signing via Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client/server: Digitally sign communications (always) (Enabled)",
            ConsolePath = "Computer Configuration > Administrative Templates > Network > Lanman Workstation",
            YouAreHere = "gpedit.msc (root)", GoTo = "Computer Configuration > Administrative Templates > Network > Lanman Workstation > 'Allow insecure guest logons' > Disabled",
            GraphicalSteps = "1) gpedit → Network → Lanman Workstation → 'Enable insecure guest logons' = Disabled. 2) secpol.msc → Security Options → 'Microsoft network client: Digitally sign communications (always)' = Enabled. 3) Same for 'Microsoft network server: …' = Enabled.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Value 1",
            IgnoreConsequence = "Relay/poisoning and guest-access attacks remain possible.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
            AlternativeToRegistry = "Prefer gpedit.msc (Lanman Workstation) + secpol.msc (Security Options) over manual registry editing." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                if (v != null && v.ToString() == "0") { currentValue = "Disabled"; status = CheckStatus.Pass; }
                else { currentValue = "Enabled"; status = CheckStatus.Fail; }
            }
            else { currentValue = "Registry Key Missing (Might be Enabled)"; status = CheckStatus.Warning; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Disabled", "Disable SMBv1 protocol via PowerShell or Group Policy to prevent vulnerabilities like EternalBlue.",
            errorMessage: errorMessage,
            description: "SMBv1 is an outdated protocol with known vulnerabilities including EternalBlue (MS17-010).",
            registryPath: $@"HKLM\{RegistryPath}\{ValueName}",
            cisReference: "CIS 18.3.2", riskScore: 90, sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegistryPath}"" /v {ValueName}",
            fixTools: new List<string> { "powershell.exe", "OptionalFeatures.exe" },
            subChecks: SubChecks));
    }

    // EDIT (گروه D - اولویت ۱): اجرای ۳ روش تست واقعی برای SMBv1
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry (HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            if (key != null)
            {
                var v = key.GetValue(ValueName);
                var passed = v != null && v.ToString() == "0";
                results.Add(new TestResult("Primary", "Registry (HKLM\\...\\LanmanServer\\Parameters\\SMB1)", passed, passed ? "SMB1 = 0 (Disabled)" : $"SMB1 = {v} (Enabled)"));
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry", false, $"Error: {ex.Message}"));
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
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase);
            results.Add(new TestResult("Cross-check", "Get-SmbServerConfiguration", passed, passed ? "EnableSMB1Protocol = False" : $"EnableSMB1Protocol = {output.Trim()}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-SmbServerConfiguration", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: Get-WindowsOptionalFeature برای SMB1Protocol
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = output.Trim().Equals("Disabled", StringComparison.OrdinalIgnoreCase);
            results.Add(new TestResult("Verification", "Get-WindowsOptionalFeature", passed, passed ? "State = Disabled" : $"State = {output.Trim()}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Get-WindowsOptionalFeature", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}