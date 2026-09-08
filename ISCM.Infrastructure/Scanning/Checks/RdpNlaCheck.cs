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
/// Phase 10.8 Batch 3: Secure RDP (Network Level Authentication) Check (Collector-only pattern).
/// 
/// SubControls (7 migrated):
///   - RDP-001.1: UserAuthentication = 1 → Boolean (NLA)
///   - RDP-001.2: MinEncryptionLevel = 3 → Integer (Enum: High)
///   - RDP-001.3: fEncryptRPCTraffic = 1 → Boolean
///   - RDP-001.4: fPromptForPassword = 1 → Boolean
///   - RDP-001.5: MaxInstanceCount → Integer (LessOrEqual 5)
///   - RDP-001.6: MaxIdleTime → Duration (LessOrEqual 15 min = 900 s)
///   - RDP-001.7: MaxDisconnectionTime → Integer (ms, LessOrEqual 60000)
/// 
/// Phase 10.8 fix: 
/// - RDP-001.6 uses Duration (ms → seconds conversion)
/// - RDP-001.7 uses Integer (raw ms from registry, catalog expects 60000)
/// </summary>
[SupportedOSPlatform("windows")]
public class RdpNlaCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string RdpTcpPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string TsPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    public override string CheckId => "RDP-001";
    public override string Name => "Secure RDP (Network Level Authentication)";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.High;

    public RdpNlaCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // RDP-001.1: NLA (UserAuthentication = 1)
        evidenceList.Add(CollectBooleanFromRegistry("RDP-001.1", RdpTcpPath, "UserAuthentication", 1));

        // RDP-001.2: Encryption level (MinEncryptionLevel = 3)
        evidenceList.Add(CollectIntegerFromRegistry("RDP-001.2", TsPath, "MinEncryptionLevel"));

        // RDP-001.3: fEncryptRPCTraffic = 1
        evidenceList.Add(CollectBooleanFromRegistry("RDP-001.3", TsPath, "fEncryptRPCTraffic", 1));

        // RDP-001.4: fPromptForPassword = 1
        evidenceList.Add(CollectBooleanFromRegistry("RDP-001.4", TsPath, "fPromptForPassword", 1));

        // RDP-001.5: MaxInstanceCount (Integer, LessOrEqual 5)
        evidenceList.Add(CollectIntegerFromRegistry("RDP-001.5", TsPath, "MaxInstanceCount"));

        // RDP-001.6: MaxIdleTime (Duration, ms → seconds, LessOrEqual 15 min = 900 s)
        evidenceList.Add(CollectDurationFromRegistryMs("RDP-001.6", TsPath, "MaxIdleTime"));

        // RDP-001.7: MaxDisconnectionTime (Integer, raw ms, LessOrEqual 60000)
        // Phase 10.8 fix: Changed from Duration to Integer to match catalog
        evidenceList.Add(CollectIntegerFromRegistry("RDP-001.7", TsPath, "MaxDisconnectionTime"));

        return Task.FromResult(evidenceList);
    }

    private Evidence CollectBooleanFromRegistry(string subControlId, string registryPath, string valueName, int expectedValue)
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
            return CreateFallbackEvidence(subControlId, valueName, registryPath, ex,
                EvidenceValue.FromBoolean(false));
        }
    }

    private Evidence CollectIntegerFromRegistry(string subControlId, string registryPath, string valueName)
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
            return CreateFallbackEvidence(subControlId, valueName, registryPath, ex,
                EvidenceValue.FromInteger(0));
        }
    }

    /// <summary>
    /// Collects a Duration from registry where value is stored in milliseconds.
    /// Converts ms → seconds for DurationValue (DurationUnit enum lacks Milliseconds).
    /// 
    /// Expected thresholds in catalog:
    ///   RDP-001.6: "15 minutes" → 900 seconds
    /// </summary>
    private Evidence CollectDurationFromRegistryMs(string subControlId, string registryPath, string valueName)
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
            var typedValue = ExtractDurationFromRegistryValueMs(rawOutput);

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
            return CreateFallbackEvidence(subControlId, valueName, registryPath, ex,
                EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Seconds)));
        }
    }

    // =========================================================================
    // Helper extractors
    // =========================================================================

    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput, int expectedValue)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == expectedValue);

        return EvidenceValue.FromBoolean(false);
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
    /// Extracts Duration from registry value stored in milliseconds.
    /// Converts ms → seconds because DurationUnit enum does not include Milliseconds.
    /// 
    /// Example: 900000 ms → 900 seconds → DurationValue(900, Seconds)
    ///          which equals "15 minutes" in the catalog comparison.
    /// </summary>
    private static EvidenceValue ExtractDurationFromRegistryValueMs(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Seconds));

        if (long.TryParse(rawOutput.Trim(), out var msValue))
        {
            // Convert milliseconds to seconds
            var seconds = msValue / 1000;
            return EvidenceValue.FromDuration(new DurationValue(seconds, DurationUnit.Seconds));
        }

        return EvidenceValue.FromDuration(new DurationValue(0, DurationUnit.Seconds));
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string valueName, string registryPath, Exception ex, EvidenceValue fallbackTypedValue)
    {
        return new Evidence
        {
            EvidenceId = $"RDP-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = valueName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = fallbackTypedValue,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }
}