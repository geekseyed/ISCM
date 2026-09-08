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
/// Phase 10.7: Process Creation Auditing Check (Collector-only pattern).
/// 
/// SubControls:
///   - PRC-001.1: Process Creation audit (Collection, SetMembership, ["Success"])
///   - PRC-001.2: Include command line (Boolean, Equals, true)
///   - PRC-001.3: Force subcategory override (Boolean, Equals, true)
/// </summary>
[SupportedOSPlatform("windows")]
public class ProcessCreationAuditingCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    private const string AuditRegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public override string CheckId => "PRC-001";
    public override string Name => "Process Creation Auditing";
    public override CheckCategory Category => CheckCategory.Audit;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public ProcessCreationAuditingCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        evidenceList.Add(await CollectProcessCreationAudit());
        evidenceList.Add(await CollectCmdLineLogging());
        evidenceList.Add(await CollectForceSubcategoryOverride());

        return evidenceList;
    }

    private async Task<Evidence> CollectProcessCreationAudit()
    {
        var subControlId = "PRC-001.1";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("auditpol", "/get /subcategory:\"Process Creation\"");
            var parsedValue = _registryParser.Parse(rawOutput, "AuditPol");
            var typedValue = ExtractAuditSettingsFromOutput(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Other,
                SourceName = "auditpol",
                AcquisitionCommand = "auditpol /get /subcategory:\"Process Creation\"",
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
            return CreateErrorEvidence(subControlId, ex);
        }
    }

    private Task<Evidence> CollectCmdLineLogging()
    {
        var subControlId = "PRC-001.2";
        var startTime = DateTime.UtcNow;

        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(AuditRegPath))
            {
                var value = key?.GetValue("ProcessCreationIncludeCmdLine_Enabled");
                rawOutput = value?.ToString() ?? "0";
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractBooleanFromRegistryValue(rawOutput);

            return Task.FromResult(new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "ProcessCreationIncludeCmdLine_Enabled",
                AcquisitionCommand = $@"reg query HKLM\{AuditRegPath} /v ProcessCreationIncludeCmdLine_Enabled",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CreateErrorEvidence(subControlId, ex));
        }
    }

    private Task<Evidence> CollectForceSubcategoryOverride()
    {
        var subControlId = "PRC-001.3";
        var startTime = DateTime.UtcNow;

        try
        {
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(LsaPath))
            {
                var value = key?.GetValue("SCENoApplyLegacyAuditPolicy");
                rawOutput = value?.ToString() ?? "0";
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var typedValue = ExtractBooleanFromRegistryValue(rawOutput);

            return Task.FromResult(new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = "SCENoApplyLegacyAuditPolicy",
                AcquisitionCommand = $@"reg query HKLM\{LsaPath} /v SCENoApplyLegacyAuditPolicy",
                RawOutput = rawOutput,
                ParsedValue = parsedValue,
                TypedValue = typedValue,
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CreateErrorEvidence(subControlId, ex));
        }
    }

    private static EvidenceValue ExtractAuditSettingsFromOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return new EvidenceValue(new List<object>(), EvidenceValueType.Collection, rawString: "(empty)");

        var enabledFlags = new List<object>();

        if (rawOutput.Contains("Success", StringComparison.OrdinalIgnoreCase) &&
            !rawOutput.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
        {
            enabledFlags.Add("Success");
        }

        if (rawOutput.Contains("Failure", StringComparison.OrdinalIgnoreCase) &&
            !rawOutput.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
        {
            enabledFlags.Add("Failure");
        }

        return new EvidenceValue(
            enabledFlags,
            EvidenceValueType.Collection,
            rawString: enabledFlags.Count > 0 ? string.Join(", ", enabledFlags) : "(none)");
    }

    /// <summary>
    /// Registry DWORD 1 = true (Enabled), 0 or missing = false (Disabled).
    /// </summary>
    private static EvidenceValue ExtractBooleanFromRegistryValue(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromBoolean(false);

        if (int.TryParse(rawOutput.Trim(), out var intValue))
            return EvidenceValue.FromBoolean(intValue == 1);

        if (rawOutput.Trim().Equals("1", StringComparison.Ordinal))
            return EvidenceValue.FromBoolean(true);

        return EvidenceValue.FromBoolean(false);
    }

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"PRC-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = "Registry + auditpol",
            RawOutput = ex.Message,
            TypedValue = null,
            Evaluation = CheckStatus.Error,
            Error = ex.Message,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    private static async Task<string> RunCommandAsync(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args)
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