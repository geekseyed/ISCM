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
/// Phase 10.8 Batch 1: NTLM & LAN Manager Authentication Check (Collector-only pattern).
/// 
/// SubControls:
///   - LM-001.1: LmCompatibilityLevel = 5 → Integer (Enum)
///   - LM-001.2: NoLMHash = 1 → Boolean true
/// </summary>
[SupportedOSPlatform("windows")]
public class LmCompatibilityCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public override string CheckId => "LM-001";
    public override string Name => "NTLM & LAN Manager Authentication";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public LmCompatibilityCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(CollectIntegerEvidence("LM-001.1", LsaPath, "LmCompatibilityLevel"));
        evidenceList.Add(CollectBooleanEvidence("LM-001.2", LsaPath, "NoLMHash", 1));
        return Task.FromResult(evidenceList);
    }

    private Evidence CollectIntegerEvidence(string subControlId, string registryPath, string valueName)
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
            var typedValue = ExtractIntegerFromRegistryValue(rawOutput);

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
            return CreateFallbackEvidence(subControlId, valueName, registryPath, ex);
        }
    }

    private Evidence CollectBooleanEvidence(string subControlId, string registryPath, string valueName, int expectedValue)
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
            return CreateFallbackEvidence(subControlId, valueName, registryPath, ex);
        }
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string valueName, string registryPath, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"LM-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = valueName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = EvidenceValue.FromInteger(0), // Conservative fallback
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    private static EvidenceValue ExtractIntegerFromRegistryValue(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        return EvidenceValue.FromInteger(0);
    }

    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput, int expectedValue)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == expectedValue);

        return EvidenceValue.FromBoolean(false);
    }
}