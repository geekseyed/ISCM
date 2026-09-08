using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.9: Disable CMD & Script Execution Check (Collector-only pattern).
/// 
/// SubControls (3 migrated):
///   - CMD-001.1: DisableCMD = 1 or 2 → Boolean true
///   - CMD-001.2: DisableCMD = 2 (scripts also blocked) → Boolean true
///   - CMD-001.3: DisallowRun with cmd.exe listed → Boolean true
/// </summary>
[SupportedOSPlatform("windows")]
public class DisableCmdCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string RegPath = @"SOFTWARE\Policies\Microsoft\Windows\System";
    private const string ValueName = "DisableCMD";

    public override string CheckId => "CMD-001";
    public override string Name => "Disable CMD & Script Execution";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public DisableCmdCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // CMD-001.1: DisableCMD = 1 or 2
        evidenceList.Add(CollectCmdBlocked("CMD-001.1"));

        // CMD-001.2: DisableCMD = 2 (scripts blocked)
        evidenceList.Add(CollectScriptsBlocked("CMD-001.2"));

        // CMD-001.3: DisallowRun with cmd.exe
        evidenceList.Add(CollectDisallowRunCmd("CMD-001.3"));

        return Task.FromResult(evidenceList);
    }

    /// <summary>
    /// CMD-001.1: Checks if DisableCMD is 1 or 2 (CMD blocked).
    /// </summary>
    private Evidence CollectCmdBlocked(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(RegPath))
            {
                var value = key?.GetValue(ValueName);
                rawOutput = value?.ToString() ?? "0";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractCmdBlockedFromRegistry(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = ValueName,
                AcquisitionCommand = $@"reg query HKLM\{RegPath} /v {ValueName}",
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
            return CreateFallbackEvidence(subControlId, ValueName, ex);
        }
    }

    /// <summary>
    /// CMD-001.2: Checks if DisableCMD = 2 (scripts also blocked).
    /// </summary>
    private Evidence CollectScriptsBlocked(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(RegPath))
            {
                var value = key?.GetValue(ValueName);
                rawOutput = value?.ToString() ?? "0";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractScriptsBlockedFromRegistry(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = ValueName,
                AcquisitionCommand = $@"reg query HKLM\{RegPath} /v {ValueName}",
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
            return CreateFallbackEvidence(subControlId, ValueName, ex);
        }
    }

    /// <summary>
    /// CMD-001.3: Checks HKCU DisallowRun = 1 with cmd.exe in the list.
    /// </summary>
    private Evidence CollectDisallowRunCmd(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            bool hasDisallowRun = false;
            bool hasCmd = false;

            using (var explorerKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
            {
                var disallowRunVal = explorerKey?.GetValue("DisallowRun");
                hasDisallowRun = disallowRunVal != null && disallowRunVal.ToString() == "1";

                if (hasDisallowRun)
                {
                    using var disallowRunKey = Registry.CurrentUser.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun");
                    if (disallowRunKey != null)
                    {
                        var values = disallowRunKey.GetValueNames();
                        hasCmd = values.Any(name =>
                            disallowRunKey.GetValue(name)?.ToString()?.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) == true);
                    }
                }
            }

            var rawOutput = $"DisallowRun={(hasDisallowRun ? "1" : "0")}, cmd.exe in list={hasCmd}";
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = EvidenceValue.FromBoolean(hasDisallowRun && hasCmd);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "DisallowRun + cmd.exe",
                AcquisitionCommand = @"reg query HKCU\...\Policies\Explorer /v DisallowRun",
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
            return CreateFallbackEvidence(subControlId, "DisallowRun", ex);
        }
    }

    // =========================================================================
    // Helper extractors
    // =========================================================================

    /// <summary>
    /// DisableCMD = 1 or 2 → true (CMD blocked), 0 or missing → false
    /// </summary>
    private static EvidenceValue ExtractCmdBlockedFromRegistry(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == 1 || intValue == 2);

        return EvidenceValue.FromBoolean(false);
    }

    /// <summary>
    /// DisableCMD = 2 → true (scripts also blocked), anything else → false
    /// </summary>
    private static EvidenceValue ExtractScriptsBlockedFromRegistry(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == 2);

        return EvidenceValue.FromBoolean(false);
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string valueName, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"CMD-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = valueName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = EvidenceValue.FromBoolean(false), // Conservative fallback
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };
    }
}