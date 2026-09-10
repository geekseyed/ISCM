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
/// Phase 12.10: MSS Legacy Registry Hardening Check (Collector-only pattern).
///
/// Verifies legacy Microsoft Security Compliance Toolkit settings that are still
/// required by CIS, DISA STIG, and other hardening benchmarks.
///
/// SubControls (8):
///   - MSS-001.1: EnableICMPRedirect (Tcpip\Parameters)
///   - MSS-001.2: PerformRouterDiscovery (Tcpip\Parameters)
///   - MSS-001.3: KeepAliveTime (Tcpip\Parameters)
///   - MSS-001.4: SafeDllSearchMode (Session Manager)
///   - MSS-001.5: ScreenSaverGracePeriod (Winlogon)
///   - MSS-001.6: WarningLevel (EventLog\Application)
///   - MSS-001.7: AutoShareServer (LanmanServer\Parameters)
///   - MSS-001.8: AutoShareWks (LanmanServer\Parameters)
/// </summary>
[SupportedOSPlatform("windows")]
public class MssLegacyCheck : BaseHardeningCheck
{
    private const string TcpipParams = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    private const string SessionManager = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    private const string Winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string EventLogApp = @"SYSTEM\CurrentControlSet\Services\EventLog\Application";
    private const string LanmanServer = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    public override string CheckId => "MSS-001";
    public override string Name => "MSS Legacy Registry Hardening";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    private static readonly (string SubControlId, string RegPath, string ValueName)[] Settings =
    {
        ("MSS-001.1", TcpipParams, "EnableICMPRedirect"),
        ("MSS-001.2", TcpipParams, "PerformRouterDiscovery"),
        ("MSS-001.3", TcpipParams, "KeepAliveTime"),
        ("MSS-001.4", SessionManager, "SafeDllSearchMode"),
        ("MSS-001.5", Winlogon, "ScreenSaverGracePeriod"),
        ("MSS-001.6", EventLogApp, "WarningLevel"),
        ("MSS-001.7", LanmanServer, "AutoShareServer"),
        ("MSS-001.8", LanmanServer, "AutoShareWks")
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