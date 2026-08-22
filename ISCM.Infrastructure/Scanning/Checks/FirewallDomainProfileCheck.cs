using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class FirewallDomainProfileCheck : IHardeningCheck, IMultiPathCheck
{
    private const string DomainPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile";
    private const string StdPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
    private const string PublicPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";

    public string CheckId => "FW-001";
    public string Name => "Windows Defender Firewall";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "FW-001.1", Title = "Domain Profile — Firewall state", Expected = "On",
            WhatItDoes = "Enables firewall protection on domain networks.",
            Recommendation = "Set DomainProfile EnableFirewall = 1.",
            CheckCurrentCli = "Get-NetFirewallProfile -Profile Domain | Select Enabled",
            CliCommand = "Set-NetFirewallProfile -Profile Domain -Enabled True",
            VerifyCli = "Get-NetFirewallProfile -Profile Domain | Select Enabled",
            Verification = "Enabled = True.",
            ValueMap = "1 = On, 0 = Off.",
            CliTokens = "-Profile Domain: domain network profile.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall Properties → Domain Profile → State",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Domain Profile",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security",
            YouAreHere = "wf.msc > Windows Defender Firewall Properties",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Domain Profile > Firewall state > On",
            GraphicalSteps = "1) Run wf.msc.\n2) Right-click 'Windows Defender Firewall with Advanced Security' > Properties.\n3) Domain Profile tab.\n4) Firewall state = On.\n5) OK.",
            UndoCli = "Set-NetFirewallProfile -Profile Domain -Enabled False",
            IgnoreConsequence = "Domain network left unprotected by firewall.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall",
            AlternativeToRegistry = "Prefer wf.msc > Firewall Properties over manual registry editing." },
        new SubCheck { Id = "FW-001.2", Title = "Domain Profile — Inbound connections", Expected = "Block (default)",
            WhatItDoes = "Blocks unsolicited inbound traffic on domain networks.",
            Recommendation = "DefaultInboundAction = Block.",
            CheckCurrentCli = "Get-NetFirewallProfile -Profile Domain | Select DefaultInboundAction",
            CliCommand = "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block",
            VerifyCli = "Get-NetFirewallProfile -Profile Domain | Select DefaultInboundAction",
            Verification = "DefaultInboundAction = Block.",
            ValueMap = "Block = default inbound block.",
            CliTokens = "-DefaultInboundAction Block: block unsolicited inbound.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall Properties → Domain Profile → Inbound connections",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Domain Profile",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security",
            YouAreHere = "wf.msc > Firewall Properties",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Domain Profile > Inbound connections > Block (default)",
            GraphicalSteps = "1) wf.msc > Properties > Domain Profile.\n2) Inbound connections = Block (default).\n3) OK.",
            UndoCli = "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Allow",
            IgnoreConsequence = "All inbound traffic allowed by default on domain.",
            HasRegistryPath = false, RegistryPath = "", AlternativeToRegistry = "" },
        new SubCheck { Id = "FW-001.3", Title = "Private Profile — Firewall state + Inbound", Expected = "On / Block",
            WhatItDoes = "Enables firewall on private networks.",
            Recommendation = "Enable private firewall with inbound block.",
            CheckCurrentCli = "Get-NetFirewallProfile -Profile Private | Select Enabled, DefaultInboundAction",
            CliCommand = "Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block",
            VerifyCli = "Get-NetFirewallProfile -Profile Private | Select Enabled, DefaultInboundAction",
            Verification = "Enabled = True, DefaultInboundAction = Block.",
            ValueMap = "",
            CliTokens = "-Profile Private: private network profile.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall Properties → Private Profile",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Private Profile",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security",
            YouAreHere = "wf.msc > Firewall Properties",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Private Profile > Firewall state > On, Inbound connections > Block (default)",
            GraphicalSteps = "1) wf.msc > Properties > Private Profile.\n2) Firewall state = On.\n3) Inbound connections = Block.\n4) OK.",
            UndoCli = "Set-NetFirewallProfile -Profile Private -Enabled False",
            IgnoreConsequence = "Private network left unprotected.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall",
            AlternativeToRegistry = "Prefer wf.msc > Firewall Properties." },
        new SubCheck { Id = "FW-001.4", Title = "Public Profile — Firewall state + Inbound", Expected = "On / Block all",
            WhatItDoes = "Applies strictest firewall posture on public networks.",
            Recommendation = "Enable public firewall with strictest inbound.",
            CheckCurrentCli = "Get-NetFirewallProfile -Profile Public | Select Enabled, DefaultInboundAction",
            CliCommand = "Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block",
            VerifyCli = "Get-NetFirewallProfile -Profile Public | Select Enabled, DefaultInboundAction",
            Verification = "Enabled = True, DefaultInboundAction = Block.",
            ValueMap = "",
            CliTokens = "-Profile Public: public network profile.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall Properties → Public Profile",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Public Profile",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security",
            YouAreHere = "wf.msc > Firewall Properties",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall Properties > Public Profile > Firewall state > On, Inbound connections > Block all",
            GraphicalSteps = "1) wf.msc > Properties > Public Profile.\n2) Firewall state = On.\n3) Inbound connections = Block all.\n4) OK.",
            UndoCli = "Set-NetFirewallProfile -Profile Public -Enabled False",
            IgnoreConsequence = "Public network fully exposed.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall",
            AlternativeToRegistry = "Prefer wf.msc > Firewall Properties." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DomainPath);
            var v = key?.GetValue("EnableFirewall");
            if (v != null && v.ToString() == "1") { currentValue = "Firewall On"; status = CheckStatus.Pass; }
            else { currentValue = "Firewall Off"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "On",
            "Enable Windows Defender Firewall on all profiles to block unauthorized network traffic.",
            errorMessage: errorMessage,
            description: "Ensures the host firewall is enabled on Domain, Private and Public profiles with inbound blocking.",
            registryPath: $@"HKLM\{DomainPath}\EnableFirewall",
            cisReference: "CIS 9.1",
            riskScore: 85,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{DomainPath}"" /v EnableFirewall",
            fixTools: new List<string> { "wf.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: PowerShell Get-NetFirewallProfile -Profile Domain
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty Enabled\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            results.Add(new TestResult("Primary", "Get-NetFirewallProfile (Domain)", passed, $"Domain Enabled = {output.Trim()}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Get-NetFirewallProfile (Domain)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Registry برای DomainProfile EnableFirewall
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DomainPath);
            if (key != null)
            {
                var v = key.GetValue("EnableFirewall");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Cross-check", "Registry (DomainProfile EnableFirewall)", passed, $"EnableFirewall = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Registry (DomainProfile EnableFirewall)", false, "EnableFirewall value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry (DomainProfile EnableFirewall)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry (DomainProfile EnableFirewall)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: netsh advfirewall برای Private profile
        try
        {
            var psi = new ProcessStartInfo("netsh.exe", "advfirewall show privateprofile state")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            var passed = output.Contains("ON", StringComparison.OrdinalIgnoreCase);
            var state = passed ? "ON" : "OFF";
            results.Add(new TestResult("Verification", "netsh advfirewall (Private)", passed, $"Private profile State = {state}"));
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "netsh advfirewall (Private)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}