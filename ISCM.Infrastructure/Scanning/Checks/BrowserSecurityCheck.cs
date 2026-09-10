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
/// Phase 12.5: Browser Security Check (Collector-only pattern).
///
/// Reads Microsoft Edge Group Policy registry keys to verify browser hardening.
/// All settings are under HKLM\SOFTWARE\Policies\Microsoft\Edge.
///
/// SubControls (8):
///   - BRW-001.1: SmartScreenEnabled (Integer, expected 1)
///   - BRW-001.2: SmartScreenPuaEnabled (Integer, expected 1)
///   - BRW-001.3: PasswordManagerEnabled (Integer, expected 0)
///   - BRW-001.4: AutofillAddressEnabled (Integer, expected 0)
///   - BRW-001.5: BlockExternalExtensions (Integer, expected 1)
///   - BRW-001.6: DefaultPopupsSetting (Integer, expected 1)
///   - BRW-001.7: DeveloperToolsAvailability (Integer, expected 2)
///   - BRW-001.8: InPrivateModeAvailability (Integer, expected 1)
/// </summary>
[SupportedOSPlatform("windows")]
public class BrowserSecurityCheck : BaseHardeningCheck
{
    private const string EdgePolicyPath = @"SOFTWARE\Policies\Microsoft\Edge";

    public override string CheckId => "BRW-001";
    public override string Name => "Browser Security (Edge)";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    private static readonly (string SubControlId, string ValueName)[] Settings =
    {
        ("BRW-001.1", "SmartScreenEnabled"),
        ("BRW-001.2", "SmartScreenPuaEnabled"),
        ("BRW-001.3", "PasswordManagerEnabled"),
        ("BRW-001.4", "AutofillAddressEnabled"),
        ("BRW-001.5", "BlockExternalExtensions"),
        ("BRW-001.6", "DefaultPopupsSetting"),
        ("BRW-001.7", "DeveloperToolsAvailability"),
        ("BRW-001.8", "InPrivateModeAvailability")
    };

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        foreach (var (subControlId, valueName) in Settings)
        {
            evidenceList.Add(CollectRegistryInteger(subControlId, valueName, startTime));
        }

        return Task.FromResult(evidenceList);
    }

    private Evidence CollectRegistryInteger(string subControlId, string valueName, DateTime startTime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(EdgePolicyPath);
            var value = key?.GetValue(valueName);
            int intValue = value != null ? Convert.ToInt32(value) : -1;
            string rawOutput = value != null ? intValue.ToString() : "Not Configured";

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                AcquisitionCommand = $@"reg query HKLM\{EdgePolicyPath} /v {valueName}",
                RawOutput = rawOutput,
                TypedValue = EvidenceValue.FromInteger(intValue),
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
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                RawOutput = $"Exception: {ex.Message}",
                TypedValue = EvidenceValue.FromInteger(-1),
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = 0
            };
        }
    }
}