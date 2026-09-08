using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.8 Batch 2: Disable LLMNR & NetBIOS Check (Collector-only pattern).
/// 
/// SubControls (7 migrated):
///   - LLN-001.1: LLMNR EnableMulticast = 0 → Boolean (inverted: 0 = true)
///   - LLN-001.2: NetBIOS via DHCP (not collectable from client side) → Boolean false (fallback)
///   - LLN-001.3: NetBIOS client prerequisite (WMI) → Integer 0 = Use DHCP
///   - LLN-001.4: NetBIOS direct disable (WMI) → Integer 2 = Disabled
///   - LLN-001.5: NetBIOS registry deployment → Integer 2
///   - LLN-001.6: WPAD WinHTTP DisableWpad = 1 → Boolean true
///   - LLN-001.7: WPAD browser AutoDetect = 0 → Boolean (inverted: 0 = true)
/// </summary>
[SupportedOSPlatform("windows")]
public class LlmnrNetbiosCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string LlmnrPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string WpadPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp";
    private const string NetBiosPath = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

    public override string CheckId => "LLN-001";
    public override string Name => "Disable LLMNR & NetBIOS";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public LlmnrNetbiosCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(CollectLlmnr("LLN-001.1"));
        evidenceList.Add(CollectNotCollectable("LLN-001.2", "DHCP scope option (server-side only)"));
        evidenceList.Add(CollectNetbiosWmi("LLN-001.3", 0)); // Use DHCP setting
        evidenceList.Add(CollectNetbiosWmi("LLN-001.4", 2)); // Disabled
        evidenceList.Add(CollectNetbiosRegistry("LLN-001.5"));
        evidenceList.Add(CollectWpad("LLN-001.6"));
        evidenceList.Add(CollectAutoDetect("LLN-001.7"));
        return Task.FromResult(evidenceList);
    }

    private Evidence CollectLlmnr(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(LlmnrPath))
            {
                var value = key?.GetValue("EnableMulticast");
                rawOutput = value?.ToString() ?? "1"; // Default: LLMNR enabled
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractInvertedBooleanFromRegistry(rawOutput, 0); // 0 = disabled = true

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "EnableMulticast",
                AcquisitionCommand = $@"reg query HKLM\{LlmnrPath} /v EnableMulticast",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallbackEvidence(subControlId, "EnableMulticast", ex);
        }
    }

    private Evidence CollectWpad(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(WpadPath))
            {
                var value = key?.GetValue("DisableWpad");
                rawOutput = value?.ToString() ?? "0";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            // Catalog expects Integer (0 or 1), not Boolean
            var typedValue = ExtractIntegerFromRegistry(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "DisableWpad",
                AcquisitionCommand = $@"reg query HKLM\{WpadPath} /v DisableWpad",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallbackEvidence(subControlId, "DisableWpad", ex);
        }
    }

    private static EvidenceValue ExtractIntegerFromRegistry(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        return EvidenceValue.FromInteger(0);
    }

    private Evidence CollectAutoDetect(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"))
            {
                var value = key?.GetValue("AutoDetect");
                rawOutput = value?.ToString() ?? "1";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractInvertedBooleanFromRegistry(rawOutput, 0); // 0 = Off = true

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "AutoDetect",
                AcquisitionCommand = @"reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings /v AutoDetect",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallbackEvidence(subControlId, "AutoDetect", ex);
        }
    }

    private Evidence CollectNetbiosWmi(string subControlId, int expectedValue)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = RunPowerShellSync(
                "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=\\\"true\\\"' | Select-Object -ExpandProperty TcpipNetbiosOptions -First 1");

            var parsedValue = _registryParser.Parse(rawOutput, "WMI");
            var typedValue = ExtractIntegerFromWmiOutput(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-CimInstance Win32_NetworkAdapterConfiguration",
                AcquisitionCommand = "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=\"true\"'",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallbackEvidence(subControlId, "Get-CimInstance Win32_NetworkAdapterConfiguration", ex);
        }
    }

    private Evidence CollectNetbiosRegistry(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = RunPowerShellSync(
                @"Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | Get-ItemProperty -Name NetbiosOptions -ErrorAction SilentlyContinue | Select-Object PSChildName,NetbiosOptions | ConvertTo-Json");

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractNetbiosOptionsFromJson(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "NetbiosOptions (all interfaces)",
                AcquisitionCommand = @"Get-ChildItem 'HKLM:\...\NetBT\Parameters\Interfaces' | Get-ItemProperty -Name NetbiosOptions",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallbackEvidence(subControlId, "NetbiosOptions", ex);
        }
    }

    private Evidence CollectNotCollectable(string subControlId, string reason)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = "Not collectable",
            RawOutput = reason,
            TypedValue = EvidenceValue.FromInteger(0), // Conservative fallback: Integer, not Boolean
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput, int expectedValue)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == expectedValue);

        return EvidenceValue.FromBoolean(false);
    }

    private static EvidenceValue ExtractInvertedBooleanFromRegistry(string rawOutput, int expectedValue)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == expectedValue);

        return EvidenceValue.FromBoolean(false);
    }

    private static EvidenceValue ExtractIntegerFromWmiOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(-1); // Unknown

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        return EvidenceValue.FromInteger(-1);
    }

    private static EvidenceValue ExtractNetbiosOptionsFromJson(string jsonOutput)
    {
        if (string.IsNullOrWhiteSpace(jsonOutput) || jsonOutput == "null")
            return EvidenceValue.FromInteger(-1); // Unknown

        // Check if all interfaces have NetbiosOptions = 2
        if (jsonOutput.Contains("\"NetbiosOptions\": 2") || jsonOutput.Contains("\"NetbiosOptions\":2"))
            return EvidenceValue.FromInteger(2);

        return EvidenceValue.FromInteger(0);
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string sourceName, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"LLN-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = sourceName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = EvidenceValue.FromBoolean(false), // Conservative fallback
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    private static string RunPowerShellSync(string command)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-Command \"{command}\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return "Process not started";

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);
            return output;
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }
}