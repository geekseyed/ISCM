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
/// Phase 10.8 Batch 2: Windows Defender Firewall Check (Collector-only pattern).
/// 
/// SubControls (4 of 16 migrated):
///   - FW-001.1: Domain Profile — Firewall state (Boolean)
///   - FW-001.2: Domain Profile — Inbound connections (Boolean, inverted: Block = true)
///   - FW-001.3: Private Profile — Firewall state + Inbound (combined Boolean)
///   - FW-001.4: Public Profile — Firewall state + Inbound (combined Boolean)
/// </summary>
[SupportedOSPlatform("windows")]
public class FirewallDomainProfileCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    public override string CheckId => "FW-001";
    public override string Name => "Windows Defender Firewall";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.High;

    public FirewallDomainProfileCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(await CollectFirewallProfile("FW-001.1", "Domain", "Enabled"));
        evidenceList.Add(await CollectFirewallProfile("FW-001.2", "Domain", "DefaultInboundAction"));
        evidenceList.Add(await CollectFirewallProfileCombined("FW-001.3", "Private"));
        evidenceList.Add(await CollectFirewallProfileCombined("FW-001.4", "Public"));
        return evidenceList;
    }

    private async Task<Evidence> CollectFirewallProfile(string subControlId, string profile, string property)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = await RunPowerShellAsync(
                $"Get-NetFirewallProfile -Profile {profile} | Select-Object -ExpandProperty {property}");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var typedValue = ExtractBooleanFromPowerShellOutput(rawOutput, property);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = $"Get-NetFirewallProfile -Profile {profile}",
                AcquisitionCommand = $"Get-NetFirewallProfile -Profile {profile} | Select-Object -ExpandProperty {property}",
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
            return CreateFallbackEvidence(subControlId, $"Get-NetFirewallProfile -Profile {profile}", ex);
        }
    }

    private async Task<Evidence> CollectFirewallProfileCombined(string subControlId, string profile)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = await RunPowerShellAsync(
                $"Get-NetFirewallProfile -Profile {profile} | Select-Object Enabled,DefaultInboundAction | ConvertTo-Json");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var typedValue = ExtractCombinedBooleanFromJson(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = $"Get-NetFirewallProfile -Profile {profile}",
                AcquisitionCommand = $"Get-NetFirewallProfile -Profile {profile} | Select-Object Enabled,DefaultInboundAction",
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
            return CreateFallbackEvidence(subControlId, $"Get-NetFirewallProfile -Profile {profile}", ex);
        }
    }

    /// <summary>
    /// Extracts Boolean from PowerShell output.
    /// For "Enabled": True → true, False → false
    /// For "DefaultInboundAction": "Block" → true (secure), "Allow" → false (insecure)
    /// </summary>
    private static EvidenceValue ExtractBooleanFromPowerShellOutput(string rawOutput, string property)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        var trimmed = rawOutput.Trim();

        if (property == "DefaultInboundAction")
        {
            // "Block" = secure (true), "Allow" = insecure (false)
            return EvidenceValue.FromBoolean(trimmed.Equals("Block", StringComparison.OrdinalIgnoreCase));
        }

        // For "Enabled": True/False
        if (trimmed.Equals("True", StringComparison.OrdinalIgnoreCase))
            return EvidenceValue.FromBoolean(true);
        if (trimmed.Equals("False", StringComparison.OrdinalIgnoreCase))
            return EvidenceValue.FromBoolean(false);

        return EvidenceValue.FromBoolean(false);
    }

    /// <summary>
    /// Extracts combined Boolean from JSON output (Enabled + DefaultInboundAction).
    /// Both must be secure: Enabled=true AND DefaultInboundAction="Block"
    /// </summary>
    private static EvidenceValue ExtractCombinedBooleanFromJson(string jsonOutput)
    {
        if (string.IsNullOrWhiteSpace(jsonOutput))
            return EvidenceValue.FromBoolean(false);

        var enabled = jsonOutput.Contains("\"Enabled\": true", StringComparison.OrdinalIgnoreCase) ||
                      jsonOutput.Contains("\"Enabled\":  true", StringComparison.OrdinalIgnoreCase);
        var blockInbound = jsonOutput.Contains("\"DefaultInboundAction\": \"Block\"", StringComparison.OrdinalIgnoreCase) ||
                          jsonOutput.Contains("\"DefaultInboundAction\":\"Block\"", StringComparison.OrdinalIgnoreCase);

        return EvidenceValue.FromBoolean(enabled && blockInbound);
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string sourceName, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"FW-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = sourceName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = EvidenceValue.FromBoolean(false), // Conservative fallback
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    private static async Task<string> RunPowerShellAsync(string command)
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

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }
}