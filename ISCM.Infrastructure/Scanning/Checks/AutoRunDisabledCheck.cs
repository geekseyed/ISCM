using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.8 Batch 1: Disable Autorun/Autoplay Check (Collector-only pattern).
/// 
/// SubControls (all Boolean from Registry):
///   - ARD-001.1: NoDriveTypeAutoRun = 255 → Boolean true
///   - ARD-001.2: NoAutorun = 1 → Boolean true
///   - ARD-001.3: NoAutoplayfornonVolume = 1 → Boolean true
/// </summary>
[SupportedOSPlatform("windows")]
public class AutoRunDisabledCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string RegPathHKLM = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";

    public override string CheckId => "ARD-001";
    public override string Name => "Disable Autorun/Autoplay";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public AutoRunDisabledCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(CollectRegistryEvidence("ARD-001.1", RegPathHKLM, "NoDriveTypeAutoRun", 255));
        evidenceList.Add(CollectRegistryEvidence("ARD-001.2", RegPathHKLM, "NoAutorun", 1));
        evidenceList.Add(CollectRegistryEvidence("ARD-001.3", RegPathHKLM, "NoAutoplayfornonVolume", 1));
        return Task.FromResult(evidenceList);
    }

    private Evidence CollectRegistryEvidence(string subControlId, string registryPath, string valueName, int expectedValue)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                var value = key?.GetValue(valueName);
                rawOutput = value?.ToString() ?? "0";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractBooleanFromRegistryValue(rawOutput, expectedValue);

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
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromBoolean(false), // Conservative fallback
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
    }

    /// <summary>
    /// Registry DWORD: specific value = true (Enabled), anything else = false.
    /// </summary>
    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput, int expectedValue)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == expectedValue);

        return EvidenceValue.FromBoolean(false);
    }
}