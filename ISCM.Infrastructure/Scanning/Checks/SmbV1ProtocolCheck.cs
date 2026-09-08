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
/// Phase 10.8 Batch 2: Disable SMBv1 Check (Collector-only pattern).
/// 
/// SubControls (5 migrated):
///   - SMB-001.1: SMB1Protocol feature removed (PowerShell Get-WindowsOptionalFeature)
///   - SMB-001.2: SMB1 server registry = 0 → Boolean (inverted)
///   - SMB-001.3: AllowInsecureGuestAuth = 0 → Boolean (inverted)
///   - SMB-001.4: Client signing = 1 → Boolean
///   - SMB-001.5: Server signing = 1 → Boolean
/// </summary>
[SupportedOSPlatform("windows")]
public class SmbV1ProtocolCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string LanmanServerPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string LanmanWorkstationPath = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

    public override string CheckId => "SMB-001";
    public override string Name => "Disable SMBv1";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.Critical;

    public SmbV1ProtocolCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(await CollectSmb1Feature("SMB-001.1"));
        evidenceList.Add(CollectRegistryBoolean("SMB-001.2", LanmanServerPath, "SMB1", 0, inverted: true));
        evidenceList.Add(CollectRegistryBoolean("SMB-001.3", LanmanWorkstationPath, "AllowInsecureGuestAuth", 0, inverted: true));
        evidenceList.Add(CollectRegistryBoolean("SMB-001.4", LanmanWorkstationPath, "RequireSecuritySignature", 1, inverted: false));
        evidenceList.Add(CollectRegistryBoolean("SMB-001.5", LanmanServerPath, "RequireSecuritySignature", 1, inverted: false));
        return evidenceList;
    }

    private async Task<Evidence> CollectSmb1Feature(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = await RunPowerShellAsync(
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            // Catalog expects String, not Boolean
            var typedValue = EvidenceValue.FromString(rawOutput.Trim());

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-WindowsOptionalFeature",
                AcquisitionCommand = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State",
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
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-WindowsOptionalFeature",
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromString("(error)"), // Conservative fallback
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    private Evidence CollectRegistryBoolean(string subControlId, string registryPath, string valueName, int expectedValue, bool inverted)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                var value = key?.GetValue(valueName);
                rawOutput = value?.ToString() ?? (inverted ? "1" : "0");
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");

            // SMB-001.2 (SMB1 registry value) needs Integer for catalog
            EvidenceValue typedValue;
            if (subControlId == "SMB-001.2")
            {
                typedValue = ExtractIntegerFromRegistry(rawOutput);
            }
            else
            {
                typedValue = inverted
                    ? ExtractInvertedBooleanFromRegistry(rawOutput, expectedValue)
                    : ExtractBooleanFromRegistry(rawOutput, expectedValue);
            }

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                AcquisitionCommand = $@"reg query HKLM\{registryPath} /v {valueName}",
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
            return CreateFallbackEvidence(subControlId, valueName, ex);
        }
    }

    private static EvidenceValue ExtractIntegerFromRegistry(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(1); // Conservative: assume SMB1 enabled

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        return EvidenceValue.FromInteger(1);
    }

    private static EvidenceValue ExtractBooleanFromRegistry(string rawOutput, int expectedValue)
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

    private static Evidence CreateFallbackEvidence(string subControlId, string sourceName, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"SMB-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
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