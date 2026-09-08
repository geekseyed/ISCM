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
/// Phase 10.8 Batch 2: Windows Update / Patch Management Check (Collector-only pattern).
/// 
/// SubControls (4 migrated):
///   - WUP-001.1: AUOptions (Integer, expected 4)
///   - WUP-001.2: WUServer configured (String URL)
///   - WUP-001.3: NoAutoRebootWithLoggedOnUsers (Integer, expected 1)
///   - WUP-001.4: Latest KB installed (String KB ID)
/// 
/// Phase 10.8 fix: WUP-001.1 and WUP-001.4 now produce Integer/String instead of Boolean
/// to match catalog ExpectedValueType declarations.
/// </summary>
[SupportedOSPlatform("windows")]
public class WindowsUpdateCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private const string AuPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    private const string WuPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

    public override string CheckId => "WUP-001";
    public override string Name => "Windows Update / Patch Management";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public WindowsUpdateCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // WUP-001.1: AUOptions → Integer (catalog expects Integer, not Boolean)
        evidenceList.Add(CollectIntegerRegistry("WUP-001.1", AuPath, "AUOptions"));

        // WUP-001.2: WUServer → String (URL)
        evidenceList.Add(CollectStringRegistry("WUP-001.2", WuPath, "WUServer"));

        // WUP-001.3: NoAutoRebootWithLoggedOnUsers → Integer (0 or 1)
        evidenceList.Add(CollectIntegerRegistry("WUP-001.3", AuPath, "NoAutoRebootWithLoggedOnUsers"));

        // WUP-001.4: Latest KB → String (KB ID from Get-HotFix)
        evidenceList.Add(await CollectLatestKb("WUP-001.4"));

        return evidenceList;
    }

    /// <summary>
    /// Collects an Integer value from registry.
    /// </summary>
    private Evidence CollectIntegerRegistry(string subControlId, string registryPath, string valueName)
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
            var typedValue = ExtractIntegerFromRegistry(rawOutput);

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

    /// <summary>
    /// Collects a String value from registry.
    /// </summary>
    private Evidence CollectStringRegistry(string subControlId, string registryPath, string valueName)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                var value = key?.GetValue(valueName);
                rawOutput = value?.ToString() ?? "";
            }
            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = EvidenceValue.FromString(rawOutput);

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

    /// <summary>
    /// Collects the latest installed KB via Get-HotFix (PowerShell).
    /// Returns String (KB ID), not Boolean.
    /// </summary>
    private async Task<Evidence> CollectLatestKb(string subControlId)
    {
        var startTime = DateTime.UtcNow;
        try
        {
            var rawOutput = await RunPowerShellAsync(
                "Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.HotFixID }");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var typedValue = EvidenceValue.FromString(rawOutput.Trim());

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-HotFix",
                AcquisitionCommand = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1",
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
                SourceName = "Get-HotFix",
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromString("(error)"),
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow
            };
        }
    }

    // =========================================================================
    // Helper extractors
    // =========================================================================

    private static EvidenceValue ExtractIntegerFromRegistry(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromInteger(intValue);

        return EvidenceValue.FromInteger(0);
    }

    private static Evidence CreateFallbackEvidence(string subControlId, string valueName, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"WUP-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = valueName,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = EvidenceValue.FromInteger(0), // Conservative fallback
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