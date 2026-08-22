using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class CredentialGuardCheck : IHardeningCheck, IMultiPathCheck
{
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string DgPath = @"SYSTEM\CurrentControlSet\Control\DeviceGuard";

    public string CheckId => "CRG-001";
    public string Name => "Credential Guard & LSA Protection";
    public CheckCategory Category => CheckCategory.System;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "CRG-001.1", Title = "Turn On Virtualization Based Security", Expected = "Enabled",
            WhatItDoes = "Enables the VBS platform required by Credential Guard.", Recommendation = "Enable the Device Guard policy 'Turn On Virtualization Based Security'.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableVirtualizationBasedSecurity",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue",
            Verification = "EnableVirtualizationBasedSecurity = 1.", ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "EnableVirtualizationBasedSecurity: VBS master switch.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > System > Device Guard > Turn On Virtualization Based Security",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Device Guard",
            YouAreHere = "gpedit.msc > Computer Configuration > Administrative Templates > System", GoTo = "Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Enabled",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > System > Device Guard.\n3) Double-click 'Turn On Virtualization Based Security'.\n4) Set the policy to Enabled.\n5) Click OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 0 -Type DWord",
            IgnoreConsequence = "VBS is not available; Credential Guard cannot be enabled.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity",
            AlternativeToRegistry = "Prefer gpedit.msc > Device Guard over manual registry editing." },
        new SubCheck { Id = "CRG-001.2", Title = "Select Platform Security Level", Expected = "Secure Boot and DMA Protection",
            WhatItDoes = "Raises the hardware-backed trust level required by VBS.", Recommendation = "Inside the 'Turn On VBS' policy dialog, set Platform Security Level = Secure Boot and DMA Protection.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name RequirePlatformSecurityFeatures -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RequirePlatformSecurityFeatures",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name RequirePlatformSecurityFeatures -Value 3 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name RequirePlatformSecurityFeatures -ErrorAction SilentlyContinue",
            Verification = "RequirePlatformSecurityFeatures = 3 (1=Secure Boot only, 3=Secure Boot + DMA Protection).", ValueMap = "1 = Secure Boot only, 3 = Secure Boot and DMA Protection.",
            CliTokens = "RequirePlatformSecurityFeatures: hardware trust level required by VBS.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard > Turn On VBS (dialog) > Select Platform Security Level",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security (policy options inside the dialog)",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Device Guard",
            YouAreHere = "gpedit.msc > Device Guard > Turn On Virtualization Based Security", GoTo = "Inside the policy dialog > Select Platform Security Level > Secure Boot and DMA Protection",
            GraphicalSteps = "1) gpedit.msc > Administrative Templates > System > Device Guard.\n2) Open 'Turn On Virtualization Based Security'.\n3) Inside the policy dialog, find 'Select Platform Security Level'.\n4) Choose 'Secure Boot and DMA Protection'.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name RequirePlatformSecurityFeatures -Value 1 -Type DWord",
            IgnoreConsequence = "VBS may run on a weaker hardware trust level.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures",
            AlternativeToRegistry = "Prefer the policy dialog options over manual registry editing." },
        new SubCheck { Id = "CRG-001.3", Title = "Credential Guard Configuration", Expected = "Enabled with UEFI lock",
            WhatItDoes = "Protects LSA secrets and stores the enablement in firmware so it cannot be casually rolled back.", Recommendation = "Inside the 'Turn On VBS' policy dialog, set Credential Guard Configuration = Enabled with UEFI lock.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LsaCfgFlags",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -ErrorAction SilentlyContinue",
            Verification = "LsaCfgFlags = 1 (1 = Enabled with UEFI lock, 2 = Enabled without UEFI lock, 0 = Disabled).", ValueMap = "1 = Enabled with UEFI lock, 2 = Enabled without UEFI lock, 0 = Disabled.",
            CliTokens = "LsaCfgFlags: Credential Guard enablement + UEFI lock flag.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard > Turn On VBS (dialog) > Credential Guard Configuration",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security (policy options inside the dialog)",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Device Guard",
            YouAreHere = "gpedit.msc > Device Guard > Turn On Virtualization Based Security", GoTo = "Inside the policy dialog > Credential Guard Configuration > Enabled with UEFI lock",
            GraphicalSteps = "1) gpedit.msc > Administrative Templates > System > Device Guard.\n2) Open 'Turn On Virtualization Based Security'.\n3) Inside the policy dialog, find 'Credential Guard Configuration'.\n4) Choose 'Enabled with UEFI lock'.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -Value 0 -Type DWord",
            IgnoreConsequence = "Credential Guard is not enabled; NTLM hashes and Kerberos tickets remain readable in LSASS memory.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags",
            AlternativeToRegistry = "Prefer the policy dialog options over manual registry editing." },
        new SubCheck { Id = "CRG-001.4", Title = "Secure Launch Configuration", Expected = "Enabled",
            WhatItDoes = "Uses System Guard Secure Launch where supported to protect boot integrity.", Recommendation = "Inside the 'Turn On VBS' policy dialog, set Secure Launch Configuration = Enabled.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name SystemGuard -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemGuard",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name SystemGuard -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name SystemGuard -ErrorAction SilentlyContinue",
            Verification = "SystemGuard = 1.", ValueMap = "1 = Enabled.",
            CliTokens = "SystemGuard: System Guard Secure Launch switch.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Device Guard > Turn On VBS (dialog) > Secure Launch Configuration",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security (policy options inside the dialog)",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Device Guard",
            YouAreHere = "gpedit.msc > Device Guard > Turn On Virtualization Based Security", GoTo = "Inside the policy dialog > Secure Launch Configuration > Enabled",
            GraphicalSteps = "1) gpedit.msc > Administrative Templates > System > Device Guard.\n2) Open 'Turn On Virtualization Based Security'.\n3) Inside the policy dialog, find 'Secure Launch Configuration'.\n4) Set to Enabled.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name SystemGuard -Value 0 -Type DWord",
            IgnoreConsequence = "Boot-integrity protection from System Guard is not used.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\SystemGuard",
            AlternativeToRegistry = "Prefer the policy dialog options over manual registry editing." },
        new SubCheck { Id = "CRG-001.5", Title = "Configure LSASS to run as a protected process (RunAsPPL)", Expected = "Enabled (with or without UEFI lock)",
            WhatItDoes = "Prevents unprotected processes (e.g. Mimikatz) from loading into or reading LSASS memory.", Recommendation = "Enable the new dedicated policy under System > Local Security Authority.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RunAsPPL",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue",
            Verification = "RunAsPPL = 1 (1 = Enabled with UEFI lock, 2 = Enabled without UEFI lock).", ValueMap = "1 = Enabled with UEFI lock, 2 = Enabled without UEFI lock, 0 = Disabled.",
            CliTokens = "RunAsPPL: LSASS protected-process level.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > System > Local Security Authority > Configure LSASS to run as a protected process",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > System > Local Security Authority > Configure LSASS to run as a protected process",
            ConsolePath = "Computer Configuration > Administrative Templates > System > Local Security Authority",
            YouAreHere = "gpedit.msc > Computer Configuration > Administrative Templates > System", GoTo = "Computer Configuration > Administrative Templates > System > Local Security Authority > Configure LSASS to run as a protected process > Enabled (with or without UEFI lock)",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > System > Local Security Authority.\n3) Double-click 'Configure LSASS to run as a protected process'.\n4) Set to Enabled.\n5) Choose 'Enabled with UEFI Lock' (preferred) or 'Enabled without UEFI Lock'.\n6) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 0 -Type DWord",
            IgnoreConsequence = "LSASS remains readable by unprotected processes; credential-dumping tools succeed.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
            AlternativeToRegistry = "Prefer the new Local Security Authority policy over manual registry editing." },
        new SubCheck { Id = "CRG-001.6", Title = "Microsoft network client: Send unencrypted password to third-party SMB servers", Expected = "Disabled",
            WhatItDoes = "Ensures SMB authentication does not fall back to plaintext password transmission.", Recommendation = "Disable this option in Local Policies > Security Options.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name EnablePlainTextPassword -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnablePlainTextPassword",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name EnablePlainTextPassword -Value 0 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name EnablePlainTextPassword -ErrorAction SilentlyContinue",
            Verification = "EnablePlainTextPassword = 0.", ValueMap = "0 = Disabled (recommended), 1 = Enabled.",
            CliTokens = "EnablePlainTextPassword: allows plaintext SMB password transmission.",
            ConsoleTool = "secpol.msc", DestinationLabel = "Security Options > Microsoft network client: Send unencrypted password to third-party SMB servers",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Send unencrypted password to third-party SMB servers",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies", GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Send unencrypted password to third-party SMB servers > Disabled",
            GraphicalSteps = "1) Run secpol.msc.\n2) Navigate to Security Settings > Local Policies > Security Options.\n3) Double-click 'Microsoft network client: Send unencrypted password to third-party SMB servers'.\n4) Set to Disabled.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name EnablePlainTextPassword -Value 1 -Type DWord",
            IgnoreConsequence = "SMB client may send plaintext passwords to non-Microsoft SMB servers.", HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options over manual registry editing." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var lsa = Registry.LocalMachine.OpenSubKey(LsaPath);
            using var dg = Registry.LocalMachine.OpenSubKey(DgPath);

            var ppl = lsa?.GetValue("RunAsPPL");
            var vbs = dg?.GetValue("EnableVirtualizationBasedSecurity");

            bool ok = (ppl != null && int.TryParse(ppl.ToString(), out int pplInt) && (pplInt == 1 || pplInt == 2))
                   && (vbs != null && int.TryParse(vbs.ToString(), out int vbsInt) && vbsInt == 1);

            currentValue = ok ? "Credential Guard + LSASS protection enabled" : "Disabled or incomplete";
            status = ok ? CheckStatus.Pass : CheckStatus.Fail;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
            currentValue = $"Error: {ex.GetType().Name}";
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Enabled",
            "Enable VBS + Credential Guard + LSASS protection to stop credential theft from memory.",
            errorMessage: errorMessage,
            description: "Uses virtualization-based security, Credential Guard and LSASS protected process to prevent credential-dumping tools from reading NTLM hashes and Kerberos tickets.",
            registryPath: $@"HKLM\{LsaPath}\RunAsPPL",
            cisReference: "CIS 5.5",
            riskScore: 85,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{LsaPath}"" /v RunAsPPL",
            fixTools: new List<string> { "gpedit.msc", "secpol.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry برای EnableVirtualizationBasedSecurity
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DgPath);
            if (key != null)
            {
                var v = key.GetValue("EnableVirtualizationBasedSecurity");
                if (v != null && v.ToString() == "1")
                {
                    results.Add(new TestResult("Primary", "Registry (VBS)", true, "EnableVirtualizationBasedSecurity = 1"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (VBS)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (VBS)", false, "DeviceGuard registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (VBS)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Get-CimInstance Win32_DeviceGuard
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CodeIntegrityPolicyEnforcementStatus\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = !string.IsNullOrWhiteSpace(output) && output.Trim() != "0";
            var details = passed ? $"CodeIntegrityPolicyEnforcementStatus = {output.Trim()}" : "Device Guard not active or not supported";
            results.Add(new TestResult("Cross-check", "Get-CimInstance (DeviceGuard)", passed, details));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-CimInstance (DeviceGuard)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: Registry برای RunAsPPL
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaPath);
            if (key != null)
            {
                var v = key.GetValue("RunAsPPL");
                if (v != null && (v.ToString() == "1" || v.ToString() == "2"))
                {
                    var level = v.ToString() == "1" ? "with UEFI lock" : "without UEFI lock";
                    results.Add(new TestResult("Verification", "Registry (RunAsPPL)", true, $"RunAsPPL = {v} ({level})"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "Registry (RunAsPPL)", false, $"Value = {v ?? "not set"}"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (RunAsPPL)", false, "LSA registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (RunAsPPL)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}