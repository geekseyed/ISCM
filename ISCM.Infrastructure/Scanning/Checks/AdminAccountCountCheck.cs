using System.Management;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects; // ← لازم برای EvidenceValue
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 11.1: AdminAccountCountCheck migrated to Collector-only pattern.
/// 
/// Counts members of the local Administrators group using multiple methods:
/// 1. PowerShell Get-LocalGroupMember (preferred, modern)
/// 2. net localgroup Administrators (fallback)
/// 3. WMI Win32_GroupUser (legacy, for backward compatibility)
/// 
/// Produces Evidence with SubControlId "ADM-001.1" and TypedValue = admin count (int).
/// Scanner will evaluate using catalog metadata (ExpectedValueType.Integer, Operator.LessOrEqual, Expected="2").
/// </summary>
[SupportedOSPlatform("windows")]
public class AdminAccountCountCheck : BaseHardeningCheck
{
    public override string CheckId => "ADM-001";
    public override string Name => "Admin Account Count";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var machineName = Environment.MachineName;

        // Try PowerShell Get-LocalGroupMember first (modern, preferred)
        var psResult = await TryPowerShellMethod();
        if (psResult.HasValue)
        {
            evidenceList.Add(CreateEvidence(
                subControlId: "ADM-001.1",
                pathId: "ADM-001.1-path-1",
                sourceType: EvidenceSourceType.PowerShell,
                sourceName: "Get-LocalGroupMember",
                command: "Get-LocalGroupMember -Group 'Administrators' | Measure-Object | Select-Object -ExpandProperty Count",
                rawOutput: $"Admin count via PowerShell: {psResult.Value}",
                typedValue: psResult.Value
            ));
            return evidenceList;
        }

        // Fallback to net localgroup
        var netResult = await TryNetLocalgroupMethod();
        if (netResult.HasValue)
        {
            evidenceList.Add(CreateEvidence(
                subControlId: "ADM-001.1",
                pathId: "ADM-001.1-path-2",
                sourceType: EvidenceSourceType.Other, // ← اصلاح: ProcessOutput → Other
                sourceName: "net localgroup",
                command: "net localgroup Administrators",
                rawOutput: $"Admin count via net localgroup: {netResult.Value}",
                typedValue: netResult.Value
            ));
            return evidenceList;
        }

        // Final fallback to WMI
        var wmiResult = TryWmiMethod(machineName);
        if (wmiResult.HasValue)
        {
            evidenceList.Add(CreateEvidence(
                subControlId: "ADM-001.1",
                pathId: "ADM-001.1-path-3",
                sourceType: EvidenceSourceType.Wmi,
                sourceName: "WMI Win32_GroupUser",
                command: $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"",
                rawOutput: $"Admin count via WMI: {wmiResult.Value}",
                typedValue: wmiResult.Value
            ));
            return evidenceList;
        }

        // All methods failed - produce error evidence
        evidenceList.Add(CreateEvidence(
            subControlId: "ADM-001.1",
            pathId: "ADM-001.1-error",
            sourceType: EvidenceSourceType.Unknown,
            sourceName: "All methods failed",
            command: "N/A",
            rawOutput: "Failed to count administrators using PowerShell, net localgroup, and WMI",
            typedValue: null
        ));

        return evidenceList;
    }

    private async Task<int?> TryPowerShellMethod()
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Measure-Object | Select-Object -ExpandProperty Count\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                if (int.TryParse(output.Trim(), out int count))
                {
                    return count;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<int?> TryNetLocalgroupMethod()
    {
        try
        {
            var psi = new ProcessStartInfo("net", "localgroup Administrators")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
            {
                var lines = output.Split('\n')
                    .Select(l => l.Trim())
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();

                int separatorIndex = -1;
                for (int i = 0; i < lines.Count; i++)
                {
                    if (lines[i].StartsWith("---"))
                    {
                        separatorIndex = i;
                        break;
                    }
                }

                if (separatorIndex >= 0)
                {
                    var memberLines = lines
                        .Skip(separatorIndex + 1)
                        .TakeWhile(l => !l.Contains("The command completed", StringComparison.OrdinalIgnoreCase))
                        .Where(l => !string.IsNullOrWhiteSpace(l))
                        .ToList();

                    return memberLines.Count;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private int? TryWmiMethod(string machineName)
    {
        try
        {
            var query = $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{machineName}',Name='Administrators'\"";
            using var searcher = new ManagementObjectSearcher(query);
            var results = searcher.Get();
            return results.Count;
        }
        catch
        {
            return null;
        }
    }

    private Evidence CreateEvidence(
        string subControlId,
        string pathId,
        EvidenceSourceType sourceType,
        string sourceName,
        string command,
        string rawOutput,
        int? typedValue)
    {
        var evidence = new Evidence
        {
            SubControlId = subControlId,
            PathId = pathId,
            SourceType = sourceType,
            SourceName = sourceName,
            AcquisitionCommand = command,
            RawOutput = rawOutput,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow
        };

        if (typedValue.HasValue)
        {
            evidence.TypedValue = new EvidenceValue(
                value: typedValue.Value,
                type: EvidenceValueType.Integer,
                unit: null,
                rawString: typedValue.Value.ToString()
            );
        }

        return evidence;
    }
}