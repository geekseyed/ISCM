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
/// Phase 10.8 Batch 1: Credential Guard & LSA Protection Check (Collector-only pattern).
/// 
/// SubControls:
///   - CRG-001.1: EnableVirtualizationBasedSecurity = 1 → Boolean true
///   - CRG-001.2: RequirePlatformSecurityFeatures = 3 → Integer (Enum)
///   - CRG-001.3: LsaCfgFlags = 1 or 2 → Integer
///   - CRG-001.4: SystemGuard = 1 → Boolean true
///   - CRG-001.5: RunAsPPL = 1 or 2 → Integer
///   - CRG-001.6: EnablePlainTextPassword = 0 → Boolean (inverted: 0 = Disabled = true)
/// </summary>
[SupportedOSPlatform("windows")]
public class CredentialGuardCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string DgPath = @"SYSTEM\CurrentControlSet\Control\DeviceGuard";
    private const string LanmanWorkstationPath = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

    public override string CheckId => "CRG-001";
    public override string Name => "Credential Guard & LSA Protection";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public CredentialGuardCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        evidenceList.Add(CollectBooleanEvidence("CRG-001.1", DgPath, "EnableVirtualizationBasedSecurity", 1));
        evidenceList.Add(CollectIntegerEvidence("CRG-001.2", DgPath, "RequirePlatformSecurityFeatures"));

        // Phase 10.8 fix: CRG-001.3 (LsaCfgFlags) — Integer 1 or 2 → Boolean true (enabled)
        evidenceList.Add(CollectMultiValueBooleanEvidence("CRG-001.3", LsaPath, "LsaCfgFlags", new[] { 1, 2 }));

        evidenceList.Add(CollectBooleanEvidence("CRG-001.4", DgPath, "SystemGuard", 1));

        // Phase 10.8 fix: CRG-001.5 (RunAsPPL) — Integer 1 or 2 → Boolean true (enabled)
        evidenceList.Add(CollectMultiValueBooleanEvidence("CRG-001.5", LsaPath, "RunAsPPL", new[] { 1, 2 }));

        evidenceList.Add(CollectInvertedBooleanEvidence("CRG-001.6", LanmanWorkstationPath, "EnablePlainTextPassword", 0));
        return Task.FromResult(evidenceList);
    }
    private Evidence CollectMultiValueBooleanEvidence(string subControlId, string registryPath, string valueName, int[] acceptedValues)
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
            var typedValue = ExtractMultiValueBooleanFromRegistry(rawOutput, acceptedValues);

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
    private static EvidenceValue ExtractMultiValueBooleanFromRegistry(string rawOutput, int[] acceptedValues)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(acceptedValues.Contains(intValue));

        return EvidenceValue.FromBoolean(false);
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

    /// <summary>
    /// Inverted boolean: registry value 0 = Disabled = Boolean true (secure).
    /// Example: EnablePlainTextPassword = 0 means plaintext is disabled (secure).
    /// </summary>
    private Evidence CollectInvertedBooleanEvidence(string subControlId, string registryPath, string valueName, int expectedValue)
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

    private static Evidence CreateFallbackEvidence(string subControlId, string valueName, string registryPath, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"CRG-001-{subControlId}",
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

    /// <summary>
    /// Registry DWORD: specific value = true (secure), anything else = false.
    /// Works for both normal (EnableLUA=1) and inverted (EnablePlainTextPassword=0) cases.
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