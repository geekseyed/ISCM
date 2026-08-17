using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class LlmnrNetbiosCheck : IHardeningCheck
{
    private const string RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string ValueName = "EnableMulticast";

    public string CheckId => "LLN-001";
    public string Name => "Disable LLMNR & NetBIOS";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "LLN-001.1", Title = "Turn off multicast name resolution (LLMNR)", Expected = "Enabled (off)", WhatItDoes = "Disables LLMNR to stop spoofing.", Recommendation = "EnableMulticast = 0.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord", Verification = "Get-ItemProperty → EnableMulticast = 0.", ConsoleTool = "gpedit.msc", DestinationLabel = "DNS Client → Turn off multicast", YouAreHere = "Registry Editor (root)", GoTo = "DNSClient → EnableMulticast = 0", GraphicalSteps = "1) gpedit → DNS Client → 'Turn off multicast name resolution' = Enabled.", HasRegistryPath = true, RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast", AlternativeToRegistry = "Prefer gpedit.msc → DNS Client over manual registry editing." },
        new SubCheck { Id = "LLN-001.2", Title = "NetBIOS over TCP/IP (all interfaces)", Expected = "2 (Disabled)", WhatItDoes = "Disables NetBIOS per adapter.", Recommendation = "NetbiosOptions = 2 on each interface.", CliCommand = "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 2 }", Verification = "Each Tcpip_* interface → NetbiosOptions = 2.", ConsoleTool = "ncpa.cpl", DestinationLabel = "Adapter → TCP/IP → WINS → Disable NetBIOS", YouAreHere = "Registry (NetBT Interfaces)", GoTo = "NetBT\\Parameters\\Interfaces\\Tcpip_* → NetbiosOptions = 2", GraphicalSteps = "1) ncpa.cpl → adapter → IPv4 → Advanced → WINS → Disable NetBIOS.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces", AlternativeToRegistry = "Prefer the adapter WINS dialog over manual registry editing." },
        new SubCheck { Id = "LLN-001.3", Title = "WPAD (optional hardening)", Expected = "Disabled", WhatItDoes = "Prevents proxy auto-discovery poisoning.", Recommendation = "Block wpad via hosts.", CliCommand = "Add-Content -Path \"$env:windir\\System32\\drivers\\etc\\hosts\" -Value '127.0.0.1 wpad'", Verification = "hosts file contains '127.0.0.1 wpad'.", ConsoleTool = "notepad", DestinationLabel = "hosts → block wpad", YouAreHere = "hosts file", GoTo = "hosts → 127.0.0.1 wpad", GraphicalSteps = "1) Edit hosts as admin. 2) Add 127.0.0.1 wpad.", HasRegistryPath = false }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath);
            var v = key?.GetValue(ValueName);
            if (v != null && v.ToString() == "0") { currentValue = "LLMNR Disabled"; status = CheckStatus.Pass; }
            else { currentValue = "LLMNR Enabled"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Disabled", "Disable legacy name-resolution protocols abused by Responder-style attacks.",
            errorMessage: errorMessage,
            description: "Disables LLMNR and NetBIOS to prevent name-resolution poisoning.",
            registryPath: $@"HKLM\{RegPath}\{ValueName}",
            cisReference: "CIS 9.1",
            riskScore: 60,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{RegPath}"" /v {ValueName}",
            fixTools: new List<string> { "gpedit.msc" },
            subChecks: SubChecks));
    }
}