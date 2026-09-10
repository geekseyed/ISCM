using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 12.6: Kernel & Exploit Protections Check (Collector-only pattern).
///
/// Reads system-wide Process Mitigations via PowerShell Get-ProcessMitigation.
/// SubControls (6):
///   - KRN-001.1: DEP (Data Execution Prevention)
///   - KRN-001.2: ASLR (High-Entropy ASLR)
///   - KRN-001.3: SEHOP
///   - KRN-001.4: CFG (Control Flow Guard)
///   - KRN-001.5: Disable Font Providers (DisableNonSystemFonts)
///   - KRN-001.6: Strict Handle Checks
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelMitigationsCheck : BaseHardeningCheck
{
    public override string CheckId => "KRN-001";
    public override string Name => "Kernel & Exploit Protections";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.Critical;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        try
        {
            // Get-ProcessMitigation -System returns an object with nested mitigation states.
            // We convert it to JSON for reliable parsing.
            string psScript = @"
                $m = Get-ProcessMitigation -System
                [PSCustomObject]@{
                    DEP = ($m.Dep.Enable -eq 'ON' -or $m.Dep.Enable -eq $true)
                    ASLR = ($m.Aslr.HighEntropy -eq 'ON' -or $m.Aslr.HighEntropy -eq $true -or $m.Aslr.Enable -eq 'ON' -or $m.Aslr.Enable -eq $true)
                    SEHOP = ($m.SeHop.Enable -eq 'ON' -or $m.SeHop.Enable -eq $true)
                    CFG = ($m.Cfg.Enable -eq 'ON' -or $m.Cfg.Enable -eq $true -or $m.Cfg.EnableExportSuppression -eq 'ON')
                    DisableFonts = ($m.FontDisable.Enable -eq 'ON' -or $m.FontDisable.Enable -eq $true)
                    StrictHandles = ($m.StrictHandleCheck.Enable -eq 'ON' -or $m.StrictHandleCheck.Enable -eq $true)
                } | ConvertTo-Json -Compress
            ";

            string rawOutput = await RunPowerShellAsync(psScript);
            var durationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

            using var doc = JsonDocument.Parse(rawOutput);
            var root = doc.RootElement;

            bool dep = GetBool(root, "DEP");
            bool aslr = GetBool(root, "ASLR");
            bool sehop = GetBool(root, "SEHOP");
            bool cfg = GetBool(root, "CFG");
            bool fonts = GetBool(root, "DisableFonts");
            bool handles = GetBool(root, "StrictHandles");

            evidenceList.Add(CreateEvidence("KRN-001.1", rawOutput, EvidenceValue.FromBoolean(dep), durationMs));
            evidenceList.Add(CreateEvidence("KRN-001.2", rawOutput, EvidenceValue.FromBoolean(aslr), durationMs));
            evidenceList.Add(CreateEvidence("KRN-001.3", rawOutput, EvidenceValue.FromBoolean(sehop), durationMs));
            evidenceList.Add(CreateEvidence("KRN-001.4", rawOutput, EvidenceValue.FromBoolean(cfg), durationMs));
            evidenceList.Add(CreateEvidence("KRN-001.5", rawOutput, EvidenceValue.FromBoolean(fonts), durationMs));
            evidenceList.Add(CreateEvidence("KRN-001.6", rawOutput, EvidenceValue.FromBoolean(handles), durationMs));
        }
        catch (Exception ex)
        {
            var fallback = $"Exception: {ex.Message}";
            evidenceList.Add(CreateFallback("KRN-001.1", fallback, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("KRN-001.2", fallback, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("KRN-001.3", fallback, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("KRN-001.4", fallback, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("KRN-001.5", fallback, EvidenceValue.FromBoolean(false)));
            evidenceList.Add(CreateFallback("KRN-001.6", fallback, EvidenceValue.FromBoolean(false)));
        }

        return evidenceList;
    }

    private static bool GetBool(JsonElement root, string prop)
    {
        return root.TryGetProperty(prop, out var v) &&
               (v.ValueKind == JsonValueKind.True || (v.ValueKind == JsonValueKind.String && v.GetString()?.ToUpper() == "TRUE"));
    }

    private Evidence CreateEvidence(string subControlId, string rawOutput, EvidenceValue typedValue, int durationMs)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-ProcessMitigation",
            AcquisitionCommand = "Get-ProcessMitigation -System",
            RawOutput = rawOutput.Length > 2000 ? rawOutput.Substring(0, 2000) + "...[truncated]" : rawOutput,
            TypedValue = typedValue,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = durationMs
        };
    }

    private Evidence CreateFallback(string subControlId, string rawOutput, EvidenceValue typedValue)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-ProcessMitigation",
            RawOutput = rawOutput,
            TypedValue = typedValue,
            Evaluation = CheckStatus.NotScanned,
            CollectedAtUtc = DateTime.UtcNow,
            CollectionDurationMs = 0
        };
    }

    private static async Task<string> RunPowerShellAsync(string command)
    {
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return "{}";

        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        return string.IsNullOrWhiteSpace(output) ? "{}" : output;
    }
}