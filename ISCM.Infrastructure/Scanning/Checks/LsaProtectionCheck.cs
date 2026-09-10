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
/// Phase 12.7: LSA Advanced Protections Check (Collector-only pattern).
///
/// Complements CRG-001 (Credential Guard) by verifying registry-level LSASS hardening
/// that works even when VBS/Credential Guard is unavailable.
///
/// SubControls (6):
///   - LSA-001.1: RunAsPPL (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL)
///   - LSA-001.2: LSASS AuditLevel (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe\AuditLevel)
///   - LSA-001.3: WDigest UseLogonCredential = 0
///   - LSA-001.4: RestrictAnonymous
///   - LSA-001.5: RestrictAnonymousSAM
///   - LSA-001.6: LimitBlankPasswordUse
/// </summary>
[SupportedOSPlatform("windows")]
public class LsaProtectionCheck : BaseHardeningCheck
{
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string WDigestPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
    private const string LsassIfEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe";

    public override string CheckId => "LSA-001";
    public override string Name => "LSA Advanced Protections";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.Critical;

    private static readonly (string SubControlId, string RegPath, string ValueName)[] Settings =
    {
        ("LSA-001.1", LsaPath, "RunAsPPL"),
        ("LSA-001.2", LsassIfEO, "AuditLevel"),
        ("LSA-001.3", WDigestPath, "UseLogonCredential"),
        ("LSA-001.4", LsaPath, "RestrictAnonymous"),
        ("LSA-001.5", LsaPath, "RestrictAnonymousSAM"),
        ("LSA-001.6", LsaPath, "LimitBlankPasswordUse")
    };

    public override Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        foreach (var (subControlId, regPath, valueName) in Settings)
        {
            evidenceList.Add(CollectRegistryInteger(subControlId, regPath, valueName, startTime));
        }

        return Task.FromResult(evidenceList);
    }

    private Evidence CollectRegistryInteger(string subControlId, string regPath, string valueName, DateTime startTime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath);
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
                AcquisitionCommand = $@"reg query HKLM\{regPath} /v {valueName}",
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