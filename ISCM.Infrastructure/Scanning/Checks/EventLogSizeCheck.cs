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
/// Phase 10.7: Event Log Size & Retention Check (Collector-only pattern).
/// 
/// 6 SubControls migrated from legacy:
///   - EVL-001.1: Application MaxSize (Integer, bytes, GreaterOrEqual 67108864)
///   - EVL-001.2: Security MaxSize (Integer, bytes, GreaterOrEqual 134217728)
///   - EVL-001.3: System MaxSize (Integer, bytes, GreaterOrEqual 67108864)
///   - EVL-001.4: Setup MaxSize (Integer, bytes, GreaterOrEqual 33554432)
///   - EVL-001.5: Retention (all 3 logs) (Integer, Equals 0 = Overwrite)
///   - EVL-001.6: AutoBackup (optional) (Boolean)
/// 
/// Phase 10.7 fix: SecurityException when reading Security log is now handled
/// gracefully (fallback to TypedValue = 0) instead of Error status.
/// Security log requires admin privilege; without it we conservatively assume 0.
/// </summary>
[SupportedOSPlatform("windows")]
public class EventLogSizeCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    private const string BasePath = @"SYSTEM\CurrentControlSet\Services\EventLog";

    public override string CheckId => "EVL-001";
    public override string Name => "Event Log Size & Retention";
    public override CheckCategory Category => CheckCategory.Audit;
    public override CheckSeverity Severity => CheckSeverity.Low;

    public EventLogSizeCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // 1-4: MaxSize for each log (Integer - bytes)
        evidenceList.Add(CollectMaxSize("EVL-001.1", "Application"));
        evidenceList.Add(CollectMaxSize("EVL-001.2", "Security"));
        evidenceList.Add(CollectMaxSize("EVL-001.3", "System"));
        evidenceList.Add(CollectMaxSize("EVL-001.4", "Setup"));

        // 5: Retention policy (using Security log as representative, all 3 should be 0)
        evidenceList.Add(CollectRetention("EVL-001.5"));

        // 6: AutoBackupLogFiles (optional) - use Security log
        evidenceList.Add(CollectAutoBackup("EVL-001.6"));

        return Task.FromResult(evidenceList);
    }

    private Evidence CollectMaxSize(string subControlId, string logName)
    {
        var startTime = DateTime.UtcNow;
        var registryPath = $@"{BasePath}\{logName}";

        try
        {
            string rawOutput;
            bool accessDenied = false;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(registryPath);
                if (key == null)
                {
                    rawOutput = "0";
                    accessDenied = true;
                }
                else
                {
                    var value = key.GetValue("MaxSize");
                    rawOutput = value?.ToString() ?? "0";
                }
            }
            catch (System.Security.SecurityException)
            {
                // Graceful degradation: admin privilege required for Security log
                rawOutput = "0";
                accessDenied = true;
            }
            catch (UnauthorizedAccessException)
            {
                rawOutput = "0";
                accessDenied = true;
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractIntegerFromRegistryValue(rawOutput);

            var finalRawOutput = accessDenied
                ? $"Access denied reading {registryPath}\\MaxSize (requires admin). Assuming 0 for conservative fallback. Original registry value unknown."
                : rawOutput;

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = $"{logName} MaxSize",
                AcquisitionCommand = $@"reg query HKLM\{registryPath} /v MaxSize",
                RawOutput = finalRawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            // Last-resort fallback: still produce a non-null TypedValue so we get Fail, not Error
            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = $"{logName} MaxSize",
                AcquisitionCommand = $@"reg query HKLM\{registryPath} /v MaxSize",
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromInteger(0), // Conservative fallback
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
    }

    /// <summary>
    /// Collects retention policy. Checks all 3 logs (Application, Security, System).
    /// Retention DWORD: 0 = Overwrite as needed (secure), other values are less secure.
    /// </summary>
    private Evidence CollectRetention(string subControlId)
    {
        var startTime = DateTime.UtcNow;

        try
        {
            var logs = new[] { "Application", "Security", "System" };
            var worstValue = 0;
            var rawDetails = new System.Text.StringBuilder();
            var anyAccessDenied = false;

            foreach (var logName in logs)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey($@"{BasePath}\{logName}");
                    if (key == null)
                    {
                        rawDetails.AppendLine($"{logName}: registry key not found");
                        anyAccessDenied = true;
                        continue;
                    }

                    var value = key.GetValue("Retention");
                    if (value != null && int.TryParse(value.ToString(), out var ret))
                    {
                        worstValue = Math.Max(worstValue, ret);
                        rawDetails.AppendLine($"{logName}: {ret}");
                    }
                    else
                    {
                        rawDetails.AppendLine($"{logName}: not set (default 0)");
                    }
                }
                catch (System.Security.SecurityException)
                {
                    rawDetails.AppendLine($"{logName}: access denied (requires admin)");
                    anyAccessDenied = true;
                    worstValue = Math.Max(worstValue, 1); // Conservative: assume insecure
                }
                catch (UnauthorizedAccessException)
                {
                    rawDetails.AppendLine($"{logName}: access denied");
                    anyAccessDenied = true;
                    worstValue = Math.Max(worstValue, 1);
                }
            }

            var rawOutput = anyAccessDenied
                ? rawDetails + "\n[Some logs required admin privilege; fallback to conservative worst-case]"
                : rawDetails.ToString();

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = EvidenceValue.FromInteger(worstValue);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "Retention (App/Sec/Sys)",
                AcquisitionCommand = @"reg query HKLM\SYSTEM\...\EventLog\{App,Sec,Sys} /v Retention",
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
                SourceName = "Retention (App/Sec/Sys)",
                AcquisitionCommand = @"reg query HKLM\SYSTEM\...\EventLog\{App,Sec,Sys} /v Retention",
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromInteger(1), // Conservative fallback (non-zero = insecure)
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
    }

    private Evidence CollectAutoBackup(string subControlId)
    {
        var startTime = DateTime.UtcNow;

        try
        {
            string rawOutput;
            bool accessDenied = false;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{BasePath}\Security");
                if (key == null)
                {
                    rawOutput = "0";
                    accessDenied = true;
                }
                else
                {
                    var value = key.GetValue("AutoBackupLogFiles");
                    rawOutput = value?.ToString() ?? "0";
                }
            }
            catch (System.Security.SecurityException)
            {
                rawOutput = "0";
                accessDenied = true;
            }
            catch (UnauthorizedAccessException)
            {
                rawOutput = "0";
                accessDenied = true;
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractBooleanFromRegistryValue(rawOutput);

            var finalRawOutput = accessDenied
                ? $"Access denied reading {BasePath}\\Security\\AutoBackupLogFiles (requires admin). Assuming Disabled (0)."
                : rawOutput;

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "AutoBackupLogFiles",
                AcquisitionCommand = @"reg query HKLM\SYSTEM\...\EventLog\Security /v AutoBackupLogFiles",
                RawOutput = finalRawOutput,
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
                SourceName = "AutoBackupLogFiles",
                AcquisitionCommand = @"reg query HKLM\SYSTEM\...\EventLog\Security /v AutoBackupLogFiles",
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromBoolean(false), // Conservative fallback
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
    }

    private static EvidenceValue ExtractIntegerFromRegistryValue(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromInteger(0);

        if (long.TryParse(rawOutput.Trim(), out var longValue))
        {
            if (longValue <= int.MaxValue && longValue >= int.MinValue)
                return EvidenceValue.FromInteger((int)longValue);
            return EvidenceValue.FromLong(longValue);
        }

        return EvidenceValue.FromInteger(0);
    }

    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == 1);

        return EvidenceValue.FromBoolean(false);
    }

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"EVL-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = "Registry",
            RawOutput = ex.Message,
            TypedValue = null,
            Evaluation = CheckStatus.Error,
            Error = ex.Message,
            CollectedAtUtc = DateTime.UtcNow
        };
    }
}