using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 12.2: Services Security Check (Collector-only pattern).
///
/// SubControls (13 migrated):
///   - SVC-001.1..7: Dangerous services must be "Stopped"
///   - SVC-001.8..13: Security services must be "Running"
///
/// Evidence collection uses two paths:
///   1) PowerShell Get-Service (preferred — structured String output)
///   2) sc query (fallback for restricted environments)
/// </summary>
[SupportedOSPlatform("windows")]
public class ServicesCheck : BaseHardeningCheck
{
    public override string CheckId => "SVC-001";
    public override string Name => "Services Security";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    // Dangerous services — must be Stopped
    private static readonly (string ServiceName, string SubControlId)[] DangerousServices =
    {
        ("RemoteRegistry", "SVC-001.1"),
        ("SSDPSRV", "SVC-001.2"),
        ("upnphost", "SVC-001.3"),
        ("TlntSvr", "SVC-001.4"),
        ("FTPSVC", "SVC-001.5"),
        ("SharedAccess", "SVC-001.6"),
        ("RpcLocator", "SVC-001.7")
    };

    // Security services — must be Running
    private static readonly (string ServiceName, string SubControlId)[] SecurityServices =
    {
        ("WinDefend", "SVC-001.8"),
        ("W32Time", "SVC-001.9"),
        ("EventLog", "SVC-001.10"),
        ("wscsvc", "SVC-001.11"),
        ("mpssvc", "SVC-001.12"),
        ("wuauserv", "SVC-001.13")
    };

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        foreach (var (serviceName, subControlId) in DangerousServices)
        {
            var status = await GetServiceStatusAsync(serviceName);
            evidenceList.Add(CreateEvidence(subControlId, serviceName, status,
                (int)(DateTime.UtcNow - startTime).TotalMilliseconds));
        }

        foreach (var (serviceName, subControlId) in SecurityServices)
        {
            var status = await GetServiceStatusAsync(serviceName);
            evidenceList.Add(CreateEvidence(subControlId, serviceName, status,
                (int)(DateTime.UtcNow - startTime).TotalMilliseconds));
        }

        return evidenceList;
    }

    private static async Task<string> GetServiceStatusAsync(string serviceName)
    {
        // Path 1: PowerShell Get-Service (preferred)
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -Command \"Get-Service -Name '{serviceName}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (!string.IsNullOrWhiteSpace(output))
                {
                    var trimmed = output.Trim();
                    if (trimmed == "Running" || trimmed == "Stopped")
                        return trimmed;
                }
            }
        }
        catch { /* fall through to sc query */ }

        // Path 2: sc query (fallback)
        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"query {serviceName}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (output.Contains("STATE              : 4 RUNNING") || output.Contains("RUNNING"))
                    return "Running";
                if (output.Contains("STATE              : 1 STOPPED") || output.Contains("STOPPED"))
                    return "Stopped";
            }
        }
        catch { /* fall through */ }

        return "Unknown";
    }

    private Evidence CreateEvidence(string subControlId, string serviceName, string status, int durationMs)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            PathId = $"{subControlId}-path-1",
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-Service",
            AcquisitionCommand = $"Get-Service -Name '{serviceName}'",
            RawOutput = status,
            TypedValue = EvidenceValue.FromString(status),
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = durationMs
        };
    }
}