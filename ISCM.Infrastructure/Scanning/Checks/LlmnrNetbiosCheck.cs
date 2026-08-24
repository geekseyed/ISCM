using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class LlmnrNetbiosCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string ValueName = "EnableMulticast";

    public string CheckId => "LLN-001";
    public string Name => "Disable LLMNR & NetBIOS";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "LLN-001.1", Title = "Turn off multicast name resolution (LLMNR)", Expected = "Enabled",
            WhatItDoes = "Disables LLMNR and reduces responder-style poisoning opportunities.",
            Recommendation = "Enable the DNS Client policy 'Turn off multicast name resolution'.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableMulticast",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableMulticast",
            Verification = "EnableMulticast = 0 (0 = off, 1 = on).",
            ValueMap = "0 = LLMNR disabled, 1 = LLMNR enabled, missing key = LLMNR enabled (default).",
            CliTokens = "EnableMulticast: master switch for LLMNR; 0 disables multicast name resolution.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Network > DNS Client > Turn off multicast name resolution",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution",
            ConsolePath = "Computer Configuration > Administrative Templates > Network > DNS Client",
            YouAreHere = "gpedit.msc > Computer Configuration > Administrative Templates > Network",
            GoTo = "Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution > Enabled",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > Network > DNS Client.\n3) Double-click 'Turn off multicast name resolution'.\n4) Set the policy to Enabled.\n5) Click OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue",
            IgnoreConsequence = "LLMNR remains active; an attacker on the local segment can poison name resolution and capture Net-NTLMv2 hashes (Responder/Pretender style).",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast",
            AlternativeToRegistry = "Prefer gpedit.msc > Administrative Templates > Network > DNS Client over manual registry editing." },
        new SubCheck { Id = "LLN-001.2", Title = "NetBIOS over TCP/IP — disable via DHCP (preferred central method)", Expected = "0x2 (Disable NetBIOS) on scope options",
            WhatItDoes = "Instructs every DHCP-served client to disable NetBIOS from the server side.",
            Recommendation = "Configure DHCP scope option 001 (Microsoft Disable Netbios Option) = 0x2.",
            CheckCurrentCli = "# Server-side only: inspect the DHCP scope on your DHCP server (not a client-side command).",
            CliCommand = "# On the DHCP server: DHCP console > Scope Options > Configure Options > Advanced > Vendor class: Microsoft Options > 001 Microsoft Disable Netbios Option > value 0x2.",
            VerifyCli = "# Clients will show 'Use NetBIOS setting from the DHCP server' on the adapter (see 11.3).",
            Verification = "DHCP scope carries option 001 = 0x2; clients in the scope have NetBIOS disabled.",
            ValueMap = "0x1 = Enable, 0x2 = Disable, default/unset = Use DHCP setting.",
            CliTokens = "Option 001 is a vendor-class Microsoft option; it is not exposed on the client.",
            ConsoleTool = "dhcpmgmt.msc", DestinationLabel = "DHCP > Scope Options > 001 Microsoft Disable Netbios Option = 0x2",
            GraphicalPathFull = "DHCP server console > IPv4 > Scope > Scope Options > Configure Options > Advanced tab > Vendor class: Microsoft Options > Code 001 Microsoft Disable Netbios Option > Byte value 0x2",
            ConsolePath = "DHCP server console > IPv4 > Scope > Scope Options",
            YouAreHere = "DHCP server console (on the DHCP server, not the endpoint)",
            GoTo = "DHCP server console > IPv4 > Scope > Scope Options > Configure Options > Advanced > Vendor class: Microsoft Options > 001 > 0x2",
            GraphicalSteps = "1) Open dhcpmgmt.msc on the DHCP server.\n2) Expand IPv4 > your scope > Scope Options.\n3) Right-click Scope Options > Configure Options.\n4) Switch to the Advanced tab, Vendor class = Microsoft Options.\n5) Check 001 Microsoft Disable Netbios Option and set byte value to 0x2.\n6) OK.",
            UndoCli = "# Remove option 001 from the DHCP scope.",
            IgnoreConsequence = "Clients fall back to local adapter default, leaving NetBIOS active on many hosts.",
            HasRegistryPath = false, RegistryPath = string.Empty,
            AlternativeToRegistry = "DHCP is the preferred central method; use adapter fallback (11.4) only if you do not control DHCP." },
        new SubCheck { Id = "LLN-001.3", Title = "NetBIOS client prerequisite — adapter set to use DHCP value", Expected = "Use NetBIOS setting from the DHCP server",
            WhatItDoes = "Allows the DHCP option 001 to take effect on the client adapter.",
            Recommendation = "Each adapter: IPv4 > Advanced > WINS > 'Use NetBIOS setting from the DHCP server'.",
            CheckCurrentCli = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,TcpipNetbiosOptions",
            CliCommand = "# Per-adapter: ncpa.cpl > adapter > IPv4 > Advanced > WINS > Default (Use DHCP setting).",
            VerifyCli = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,TcpipNetbiosOptions",
            Verification = "TcpipNetbiosOptions = 0 (Default / Use DHCP setting).",
            ValueMap = "0 = Use DHCP setting, 1 = Enable NetBIOS, 2 = Disable NetBIOS.",
            CliTokens = "TcpipNetbiosOptions: per-adapter NetBIOS mode.",
            ConsoleTool = "ncpa.cpl", DestinationLabel = "Network Connections > Adapter > IPv4 > Advanced > WINS",
            GraphicalPathFull = "Control Panel > Network and Sharing Center > Change adapter settings > right-click adapter > Properties > Internet Protocol Version 4 (TCP/IPv4) > Properties > Advanced > WINS tab > Default (Use NetBIOS setting from the DHCP server)",
            ConsolePath = "ncpa.cpl > adapter properties > IPv4 > Advanced > WINS",
            YouAreHere = "Network Connections (ncpa.cpl)",
            GoTo = "Network Connections > Adapter > Properties > IPv4 > Advanced > WINS > Default",
            GraphicalSteps = "1) Run ncpa.cpl.\n2) Right-click the target adapter > Properties.\n3) Select Internet Protocol Version 4 (TCP/IPv4) > Properties.\n4) Advanced > WINS tab.\n5) Select 'Default (Use NetBIOS setting from the DHCP server)'.\n6) OK on all dialogs.",
            UndoCli = "# Switch the WINS radio button to 'Enable NetBIOS over TCP/IP'.",
            IgnoreConsequence = "Adapter-level NetBIOS setting overrides the DHCP option, so even with DHCP 0x2 the client may keep NetBIOS on.",
            HasRegistryPath = false, RegistryPath = string.Empty,
            AlternativeToRegistry = "Prefer the WINS tab UI or DHCP; use the registry method (11.5) only for central deployment." },
        new SubCheck { Id = "LLN-001.4", Title = "NetBIOS over TCP/IP — direct per-adapter disable (no DHCP control)", Expected = "Disable NetBIOS over TCP/IP on every adapter",
            WhatItDoes = "Disables NetBIOS directly on the adapter when you cannot control DHCP.",
            Recommendation = "Each adapter: IPv4 > Advanced > WINS > 'Disable NetBIOS over TCP/IP'.",
            CheckCurrentCli = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,TcpipNetbiosOptions",
            CliCommand = "# Per-adapter: ncpa.cpl > adapter > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP.",
            VerifyCli = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,TcpipNetbiosOptions",
            Verification = "TcpipNetbiosOptions = 2 (Disabled) on every enabled adapter.",
            ValueMap = "2 = Disabled.",
            CliTokens = "TcpipNetbiosOptions: 2 forces NetBIOS off on that adapter.",
            ConsoleTool = "ncpa.cpl", DestinationLabel = "Network Connections > Adapter > IPv4 > Advanced > WINS > Disable",
            GraphicalPathFull = "Control Panel > Network and Sharing Center > Change adapter settings > right-click adapter > Properties > IPv4 > Properties > Advanced > WINS tab > Disable NetBIOS over TCP/IP",
            ConsolePath = "ncpa.cpl > adapter properties > IPv4 > Advanced > WINS",
            YouAreHere = "Network Connections (ncpa.cpl)",
            GoTo = "Network Connections > Adapter > Properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP",
            GraphicalSteps = "1) Run ncpa.cpl.\n2) Right-click the adapter > Properties.\n3) IPv4 > Properties > Advanced > WINS.\n4) Select 'Disable NetBIOS over TCP/IP'.\n5) OK on all dialogs.\n6) Repeat on every active adapter.",
            UndoCli = "# Switch the WINS radio button back to 'Default' or 'Enable'.",
            IgnoreConsequence = "NetBIOS name resolution remains exposed; attackers can perform NBT-NS poisoning and capture credentials.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*\NetbiosOptions",
            AlternativeToRegistry = "Prefer the WINS tab UI for a single endpoint; use 11.5 for central GPO-based deployment." },
        new SubCheck { Id = "LLN-001.5", Title = "NetBIOS over TCP/IP — registry deployment (central GPO/GPP)", Expected = "NetbiosOptions = 2 under every Tcpip_* interface",
            WhatItDoes = "Enforces NetBIOS off on every adapter through Group Policy Preferences (Registry).",
            Recommendation = "Deploy via Computer Configuration > Preferences > Windows Settings > Registry.",
            CheckCurrentCli = "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | Get-ItemProperty -Name NetbiosOptions -ErrorAction SilentlyContinue | Select-Object PSChildName,NetbiosOptions",
            CliCommand = "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -Type DWord }",
            VerifyCli = "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | Get-ItemProperty -Name NetbiosOptions -ErrorAction SilentlyContinue",
            Verification = "Every Tcpip_<GUID> subkey shows NetbiosOptions = 2.",
            ValueMap = "2 = Disable NetBIOS.",
            CliTokens = "NetbiosOptions under each interface: 0 = Default, 1 = Enable, 2 = Disable.",
            ConsoleTool = "gpmc.msc", DestinationLabel = "GPO > Preferences > Windows Settings > Registry > HKLM\\SYSTEM\\...\\Tcpip_*\\NetbiosOptions = 2",
            GraphicalPathFull = "Computer Configuration > Preferences > Windows Settings > Registry > New > Registry Item > Hive HKLM > Key Path SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_* > Value name NetbiosOptions > Value data 2 (REG_DWORD) — use Item-level targeting to apply to all network interfaces.",
            ConsolePath = "Computer Configuration > Preferences > Windows Settings > Registry",
            YouAreHere = "Group Policy Management (gpmc.msc) editing a GPO",
            GoTo = "Computer Configuration > Preferences > Windows Settings > Registry > new item targeting Tcpip_* interfaces",
            GraphicalSteps = "1) Open gpmc.msc, edit the hardening GPO.\n2) Computer Configuration > Preferences > Windows Settings > Registry.\n3) Right-click > New > Registry Item.\n4) Action: Update. Hive: HKEY_LOCAL_MACHINE.\n5) Key Path: SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_<adapter-GUID>.\n6) Value name: NetbiosOptions. Value type: REG_DWORD. Value data: 2.\n7) Use Item-level targeting (Registry match on the wildcard key) to cover all adapters.\n8) OK. Run gpupdate /force on the endpoint.",
            UndoCli = "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 0 -Type DWord }",
            IgnoreConsequence = "No central enforcement of NetBIOS state; each host must be configured manually.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*\NetbiosOptions",
            AlternativeToRegistry = "Use this method only when DHCP (11.2) is not available; prefer DHCP for new deployments." },
        new SubCheck { Id = "LLN-001.6", Title = "WPAD — disable WinHTTP proxy auto-discovery (central)", Expected = "DisableWpad = 1",
            WhatItDoes = "Disables WPAD at the WinHTTP layer so system services cannot be poisoned by a rogue wpad.dat.",
            Recommendation = "Deploy via Computer Configuration > Preferences > Windows Settings > Registry.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp' -Name DisableWpad -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableWpad",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp' -Name DisableWpad -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp' -Name DisableWpad -ErrorAction SilentlyContinue",
            Verification = "DisableWpad = 1.",
            ValueMap = "1 = WPAD disabled for WinHTTP.",
            CliTokens = "DisableWpad: WinHTTP master switch for proxy auto-discovery.",
            ConsoleTool = "gpmc.msc", DestinationLabel = "GPO > Preferences > Windows Settings > Registry > HKLM\\...\\WinHttp\\DisableWpad = 1",
            GraphicalPathFull = "Computer Configuration > Preferences > Windows Settings > Registry > New > Registry Item > Hive HKLM > Key Path SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp > Value name DisableWpad > Value data 1 (REG_DWORD)",
            ConsolePath = "Computer Configuration > Preferences > Windows Settings > Registry",
            YouAreHere = "Group Policy Management (gpmc.msc) editing a GPO",
            GoTo = "Computer Configuration > Preferences > Windows Settings > Registry > WinHttp > DisableWpad = 1",
            GraphicalSteps = "1) Open gpmc.msc, edit the hardening GPO.\n2) Computer Configuration > Preferences > Windows Settings > Registry.\n3) Right-click > New > Registry Item.\n4) Action: Update. Hive: HKEY_LOCAL_MACHINE.\n5) Key Path: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp.\n6) Value name: DisableWpad. Value type: REG_DWORD. Value data: 1.\n7) OK. Run gpupdate /force on the endpoint.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp' -Name DisableWpad -ErrorAction SilentlyContinue",
            IgnoreConsequence = "WinHTTP clients (Windows Update, many services) may fetch a rogue wpad.dat and route traffic through an attacker-controlled proxy.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad",
            AlternativeToRegistry = "Prefer central GPO/GPP deployment over local registry editing." },
        new SubCheck { Id = "LLN-001.7", Title = "WPAD — disable browser/user-layer auto-detect (optional hardening)", Expected = "Automatically detect settings = Off",
            WhatItDoes = "Turns off proxy auto-discovery in the user/browser layer that the WinHTTP switch does not cover.",
            Recommendation = "Uncheck 'Automatically detect settings' in Internet Options > LAN Settings.",
            CheckCurrentCli = "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoDetect -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoDetect",
            CliCommand = "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoDetect -Value 0 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoDetect -ErrorAction SilentlyContinue",
            Verification = "AutoDetect = 0 (Off).",
            ValueMap = "0 = Off, 1 = On (default).",
            CliTokens = "AutoDetect under HKCU\\...\\Internet Settings controls the 'Automatically detect settings' checkbox.",
            ConsoleTool = "inetcpl.cpl", DestinationLabel = "Internet Options > Connections > LAN settings > Automatically detect settings = Off",
            GraphicalPathFull = "Internet Options (inetcpl.cpl) > Connections tab > LAN settings > uncheck 'Automatically detect settings' > OK",
            ConsolePath = "inetcpl.cpl > Connections > LAN settings",
            YouAreHere = "Internet Options (inetcpl.cpl)",
            GoTo = "Internet Options > Connections > LAN settings > uncheck 'Automatically detect settings'",
            GraphicalSteps = "1) Run inetcpl.cpl.\n2) Connections tab > LAN settings.\n3) Uncheck 'Automatically detect settings'.\n4) OK > OK.\n5) For central deployment, push this HKCU value via GPO Preferences (User Configuration).",
            UndoCli = "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoDetect -Value 1 -Type DWord",
            IgnoreConsequence = "Browsers and WinINET-based apps may still fetch a rogue wpad.dat even after the WinHTTP hardening (11.6).",
            HasRegistryPath = true, RegistryPath = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\AutoDetect",
            AlternativeToRegistry = "Prefer the LAN Settings UI for single endpoints; use GPO Preferences (HKCU) for central deployment." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // 1. LLMNR (EnableMulticast = 0)
            using var dnsKey = Registry.LocalMachine.OpenSubKey(RegPath);
            var llmnrVal = dnsKey?.GetValue(ValueName);
            if (llmnrVal != null && int.TryParse(llmnrVal.ToString(), out int llmnr) && llmnr == 0) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 2. WPAD WinHTTP (DisableWpad = 1)
            using var winhttpKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp");
            var wpadVal = winhttpKey?.GetValue("DisableWpad");
            if (wpadVal != null && int.TryParse(wpadVal.ToString(), out int wpad) && wpad == 1) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            // 3. NetBIOS per-adapter (check first adapter's NetbiosOptions)
            using var netbtKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces");
            if (netbtKey != null)
            {
                var subKeys = netbtKey.GetSubKeyNames();
                bool allDisabled = true;
                bool foundAny = false;
                foreach (var subKey in subKeys.Where(s => s.StartsWith("Tcpip_", StringComparison.OrdinalIgnoreCase)))
                {
                    using var ifaceKey = netbtKey.OpenSubKey(subKey);
                    var optVal = ifaceKey?.GetValue("NetbiosOptions");
                    if (optVal != null && int.TryParse(optVal.ToString(), out int opt))
                    {
                        foundAny = true;
                        if (opt != 2) allDisabled = false;
                    }
                }
                statuses.Add(foundAny && allDisabled ? CheckStatus.Pass : CheckStatus.Fail);
            }
            else
            {
                statuses.Add(CheckStatus.Fail);
            }

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} LLMNR/NetBIOS/WPAD settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "LLMNR, NetBIOS, and WPAD disabled",
                "Disable LLMNR and NetBIOS across all layers to prevent responder/NBT-NS/WPAD poisoning.",
                errorMessage: string.Empty,
                description: "Disables legacy name-resolution and proxy auto-discovery protocols commonly abused by local attackers (Responder, NBT-NS poisoning, WPAD poisoning).",
                registryPath: $@"HKLM\{RegPath}\{ValueName}",
                cisReference: "CIS 18.5.14.1", riskScore: 75, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
                fixTools: new List<string> { "gpedit.msc", "ncpa.cpl", "dhcpmgmt.msc", "gpmc.msc", "inetcpl.cpl" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Disables legacy name-resolution and proxy auto-discovery protocols commonly abused by local attackers.",
                registryPath: $@"HKLM\{RegPath}\{ValueName}",
                cisReference: "CIS 18.5.14.1", riskScore: 75, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
                fixTools: new List<string> { "gpedit.msc", "ncpa.cpl", "dhcpmgmt.msc", "gpmc.msc", "inetcpl.cpl" },
                subChecks: SubChecks));
        }
    }

    // Preserved: 3-Test Verification
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry HKLM برای LLMNR (EnableMulticast)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient");
            if (key != null)
            {
                var v = key.GetValue("EnableMulticast");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 0;
                    results.Add(new TestResult("Primary", "Registry (LLMNR)", passed, $"EnableMulticast = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (LLMNR)", false, "EnableMulticast value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (LLMNR)", false, "DNSClient registry key not found (LLMNR enabled by default)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (LLMNR)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: WMI برای NetBIOS over TCP/IP (TcpipNetbiosOptions)
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=\\\"true\\\"' | Select-Object -ExpandProperty TcpipNetbiosOptions -First 1\"")
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
                if (!string.IsNullOrWhiteSpace(output) && int.TryParse(output.Trim(), out int netbios))
                {
                    var passed = netbios == 2 || netbios == 0;
                    var desc = netbios switch
                    {
                        0 => "Default (Use DHCP setting)",
                        1 => "Enable NetBIOS",
                        2 => "Disable NetBIOS",
                        _ => $"Unknown value: {netbios}"
                    };
                    results.Add(new TestResult("Cross-check", "WMI (NetBIOS)", passed, $"TcpipNetbiosOptions = {netbios} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "WMI (NetBIOS)", false, "Could not query NetBIOS setting"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "WMI (NetBIOS)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: Registry HKLM برای WPAD (DisableWpad)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp");
            if (key != null)
            {
                var v = key.GetValue("DisableWpad");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Verification", "Registry (WPAD)", passed, $"DisableWpad = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "Registry (WPAD)", false, "DisableWpad value not found (WPAD enabled by default)"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (WPAD)", false, "WinHttp registry key not found (WPAD enabled by default)"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (WPAD)", false, $"Error: {ex.Message}"));
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
}