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
/// Phase 10.7: PowerShell Logging Check (Collector-only pattern).
/// 
/// SubControls (all Boolean from Registry):
///   - PSH-001.1: EnableScriptBlockLogging (Required)
///   - PSH-001.2: EnableModuleLogging (Required)
///   - PSH-001.3: EnableScriptBlockInvocationLogging (Optional)
/// </summary>
[SupportedOSPlatform("windows")]
public class PowerShellLoggingCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    private const string ScriptBlockPath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
    private const string ModulePath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";

    public override string CheckId => "PSH-001";
    public override string Name => "PowerShell Script Block Logging";
    public override CheckCategory Category => CheckCategory.Audit;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public PowerShellLoggingCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        evidenceList.Add(CollectRegistryBoolean(
            "PSH-001.1", ScriptBlockPath, "EnableScriptBlockLogging"));

        evidenceList.Add(CollectRegistryBoolean(
            "PSH-001.2", ModulePath, "EnableModuleLogging"));

        evidenceList.Add(CollectRegistryBoolean(
            "PSH-001.3", ScriptBlockPath, "EnableScriptBlockInvocationLogging"));

        return Task.FromResult(evidenceList);
    }

    private Evidence CollectRegistryBoolean(string subControlId, string registryPath, string valueName)
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
            var typedValue = ExtractBooleanFromRegistryValue(rawOutput);

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
            return CreateErrorEvidence(subControlId, ex);
        }
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

        return EvidenceValue.FromBoolean(false);
    }

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"PSH-001-{subControlId}",
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