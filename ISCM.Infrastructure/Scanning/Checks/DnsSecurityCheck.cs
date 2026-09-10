using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 12.4: DNS Security Check (Collector-only pattern).
///
/// SubControls (6):
///   - DNS-001.1: DNS over HTTPS (Registry EnableDoH, Integer)
///   - DNS-001.2: Smart Multi-homed Name Resolution (Registry, Integer)
///   - DNS-001.3: mDNS service disabled (Get-Service, String)
///   - DNS-001.4: HOSTS file size (FileSystem, Integer bytes)
///   - DNS-001.5: DNS Client service running (Get-Service, String)
///   - DNS-001.6: Negative SOA cache disabled (Registry, Integer)
///
/// Note: LLMNR and NetBIOS are intentionally NOT covered here —
/// they are already handled by LlmnrNetbiosCheck (LLN-001) in Phase 11.
/// </summary>
[SupportedOSPlatform("windows")]
public class DnsSecurityCheck : BaseHardeningCheck
{
    private const string DnsCacheParams = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
    private const string DnsClientPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

    public override string CheckId => "DNS-001";
    public override string Name => "DNS Security";
    public override CheckCategory Category => CheckCategory.Network;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        // DNS-001.1: DNS over HTTPS (EnableDoH)
        evidenceList.Add(CollectRegInteger("DNS-001.1", DnsCacheParams, "EnableDoH", startTime));

        // DNS-001.2: Smart Multi-homed Name Resolution
        evidenceList.Add(CollectRegIntegerInverse("DNS-001.2", DnsClientPolicy,
            "DisableSmartMultiHomedNameResolution", startTime));

        // DNS-001.3: mDNS service disabled (may not exist on all systems)
        evidenceList.Add(await CollectServiceStatus("DNS-001.3", "mdnssvc", startTime));

        // DNS-001.4: HOSTS file size
        evidenceList.Add(CollectHostsFileSize("DNS-001.4", startTime));

        // DNS-001.5: DNS Client service (Dnscache) running
        evidenceList.Add(await CollectServiceStatus("DNS-001.5", "Dnscache", startTime));

        // DNS-001.6: Negative SOA cache (NegativeCacheTime)
        evidenceList.Add(CollectRegInteger("DNS-001.6", DnsCacheParams, "NegativeCacheTime", startTime));

        return evidenceList;
    }

    private Evidence CollectRegInteger(string subId, string path, string valueName, DateTime startTime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var value = key?.GetValue(valueName);
            int intValue = value != null ? Convert.ToInt32(value) : 0;

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subId}",
                SubControlId = subId,
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                AcquisitionCommand = $@"reg query HKLM\{path} /v {valueName}",
                RawOutput = intValue.ToString(),
                TypedValue = EvidenceValue.FromInteger(intValue),
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallback(subId, valueName, EvidenceValue.FromInteger(0), ex);
        }
    }

    /// <summary>
    /// For SMHNR: registry value 1 = disabled (good), 0 or missing = enabled (leaking).
    /// We collect the raw "disabled" flag (1=disabled, 0=enabled).
    /// Catalog expects 0 (disabled-flag missing/enabled) vs 1 (disabled-flag set).
    /// </summary>
    private Evidence CollectRegIntegerInverse(string subId, string path, string valueName, DateTime startTime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var value = key?.GetValue(valueName);
            // If DisableSmartMultiHomedNameResolution exists and = 1 → SMHNR disabled (safe)
            int disabledFlag = value != null ? Convert.ToInt32(value) : 0;

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subId}",
                SubControlId = subId,
                TechnicalCheckId = CheckId,
                SourceType = EvidenceSourceType.Registry,
                SourceName = valueName,
                AcquisitionCommand = $@"reg query HKLM\{path} /v {valueName}",
                RawOutput = disabledFlag.ToString(),
                TypedValue = EvidenceValue.FromInteger(disabledFlag),
                Evaluation = CheckStatus.NotScanned,
                CollectedAtUtc = DateTime.UtcNow,
                CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            return CreateFallback(subId, valueName, EvidenceValue.FromInteger(0), ex);
        }
    }

    private async Task<Evidence> CollectServiceStatus(string subId, string serviceName, DateTime startTime)
    {
        string status = "Unknown";
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -Command \"Get-Service -Name '{serviceName}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                if (!string.IsNullOrWhiteSpace(output))
                    status = output.Trim();
                else
                    status = "NotInstalled";
            }
        }
        catch { status = "Error"; }

        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subId}",
            SubControlId = subId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-Service",
            AcquisitionCommand = $"Get-Service -Name '{serviceName}'",
            RawOutput = status,
            TypedValue = EvidenceValue.FromString(status),
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
        };
    }

    private Evidence CollectHostsFileSize(string subId, DateTime startTime)
    {
        var hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");
        long sizeBytes = 0;
        try
        {
            if (File.Exists(hostsPath))
                sizeBytes = new FileInfo(hostsPath).Length;
        }
        catch { /* leave 0 */ }

        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subId}",
            SubControlId = subId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.File,
            SourceName = "hosts",
            AcquisitionCommand = $"Get-Item {hostsPath} | Select-Object Length",
            RawOutput = sizeBytes.ToString(),
            TypedValue = EvidenceValue.FromInteger((int)sizeBytes),
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
        };
    }

    private Evidence CreateFallback(string subId, string source, EvidenceValue typedValue, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subId}",
            SubControlId = subId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.Registry,
            SourceName = source,
            RawOutput = $"Exception: {ex.Message}",
            TypedValue = typedValue,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = 0
        };
    }
}