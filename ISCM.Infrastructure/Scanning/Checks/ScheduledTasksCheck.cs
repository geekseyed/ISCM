using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 12.3: Scheduled Tasks Security Check (Collector-only pattern).
///
/// Identifies suspicious scheduled tasks commonly used by malware for persistence:
///   - STK-001.1: Total task count (visibility baseline)
///   - STK-001.2: Tasks with executables in AppData/Temp/Downloads (malware locations)
///   - STK-001.3: Tasks with boot/logon triggers (persistence)
///   - STK-001.4: Hidden tasks (malware hides itself)
///   - STK-001.5: PowerShell/cmd/wscript/cscript actions (script-based persistence)
///   - STK-001.6: Non-Microsoft authored tasks (third-party attack surface)
///
/// Single PowerShell invocation returns JSON with all task metadata.
/// </summary>
[SupportedOSPlatform("windows")]
public class ScheduledTasksCheck : BaseHardeningCheck
{
    public override string CheckId => "STK-001";
    public override string Name => "Scheduled Tasks Security";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();
        var startTime = DateTime.UtcNow;

        try
        {
            string psScript = @"
                $ErrorActionPreference = 'SilentlyContinue'
                $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.State -ne 'Unknown' }
                $result = foreach ($t in $tasks) {
                    $action = $t.Actions | Select-Object -First 1
                    [PSCustomObject]@{
                        Name       = $t.TaskName
                        Path       = $t.TaskPath
                        Execute    = if ($action -and $action.Execute) { $action.Execute } else { '' }
                        Arguments  = if ($action -and $action.Arguments) { $action.Arguments } else { '' }
                        Author     = if ($t.Author) { $t.Author } else { '' }
                        IsMs       = ($t.TaskPath -like '\Microsoft\*' -or $t.Author -match 'Microsoft|Windows')
                        Hidden     = $t.Settings.Hidden -eq $true
                        TriggerKinds = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '|'
                    }
                }
                $result | ConvertTo-Json -Compress -Depth 4
            ";

            string rawOutput = await RunPowerShellAsync(psScript);
            var durationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

            // Parse safely — handle both array and single-object JSON
            var tasks = ParseTasks(rawOutput);

            int totalCount = tasks.Count;
            int suspiciousPathCount = tasks.Count(t => HasSuspiciousPath(t.Execute));
            int startupLogonCount = tasks.Count(t => HasStartupOrLogonTrigger(t.TriggerKinds));
            int hiddenCount = tasks.Count(t => t.Hidden);
            int scriptActionCount = tasks.Count(t => HasScriptAction(t.Execute));
            int nonMicrosoftCount = tasks.Count(t => !t.IsMicrosoft);

            evidenceList.Add(CreateEvidence("STK-001.1", rawOutput, EvidenceValue.FromInteger(totalCount), durationMs));
            evidenceList.Add(CreateEvidence("STK-001.2", rawOutput, EvidenceValue.FromInteger(suspiciousPathCount), durationMs));
            evidenceList.Add(CreateEvidence("STK-001.3", rawOutput, EvidenceValue.FromInteger(startupLogonCount), durationMs));
            evidenceList.Add(CreateEvidence("STK-001.4", rawOutput, EvidenceValue.FromInteger(hiddenCount), durationMs));
            evidenceList.Add(CreateEvidence("STK-001.5", rawOutput, EvidenceValue.FromInteger(scriptActionCount), durationMs));
            evidenceList.Add(CreateEvidence("STK-001.6", rawOutput, EvidenceValue.FromInteger(nonMicrosoftCount), durationMs));
        }
        catch (Exception ex)
        {
            var fallback = $"Exception: {ex.Message}";
            evidenceList.Add(CreateFallback("STK-001.1", fallback, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("STK-001.2", fallback, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("STK-001.3", fallback, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("STK-001.4", fallback, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("STK-001.5", fallback, EvidenceValue.FromInteger(0)));
            evidenceList.Add(CreateFallback("STK-001.6", fallback, EvidenceValue.FromInteger(0)));
        }

        return evidenceList;
    }

    private static List<TaskInfo> ParseTasks(string json)
    {
        var result = new List<TaskInfo>();
        if (string.IsNullOrWhiteSpace(json)) return result;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            IEnumerable<JsonElement> elements = root.ValueKind switch
            {
                JsonValueKind.Array => root.EnumerateArray(),
                JsonValueKind.Object => new[] { root },
                _ => Array.Empty<JsonElement>()
            };

            foreach (var el in elements)
            {
                result.Add(new TaskInfo
                {
                    Execute = SafeGet(el, "Execute"),
                    Author = SafeGet(el, "Author"),
                    IsMicrosoft = el.TryGetProperty("IsMs", out var isMs) && isMs.GetBoolean(),
                    Hidden = el.TryGetProperty("Hidden", out var hid) && hid.GetBoolean(),
                    TriggerKinds = SafeGet(el, "TriggerKinds")
                });
            }
        }
        catch
        {
            // Return whatever parsed, may be empty
        }

        return result;
    }

    private static string SafeGet(JsonElement el, string prop)
    {
        return el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? string.Empty : string.Empty;
    }

    private static bool HasSuspiciousPath(string execute)
    {
        if (string.IsNullOrWhiteSpace(execute)) return false;
        var lower = execute.ToLowerInvariant();
        return lower.Contains("\\appdata\\")
            || lower.Contains("\\temp\\")
            || lower.Contains("\\downloads\\")
            || lower.Contains("\\programdata\\")
            || lower.Contains("\\users\\public\\");
    }

    private static bool HasStartupOrLogonTrigger(string triggerKinds)
    {
        if (string.IsNullOrWhiteSpace(triggerKinds)) return false;
        return triggerKinds.Contains("MSFT_TaskBootTrigger", StringComparison.OrdinalIgnoreCase)
            || triggerKinds.Contains("MSFT_TaskLogonTrigger", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasScriptAction(string execute)
    {
        if (string.IsNullOrWhiteSpace(execute)) return false;
        var lower = execute.ToLowerInvariant();
        return lower.Contains("powershell.exe")
            || lower.Contains("pwsh.exe")
            || lower.Contains("cmd.exe")
            || lower.Contains("wscript.exe")
            || lower.Contains("cscript.exe")
            || lower.Contains("mshta.exe");
    }

    private Evidence CreateEvidence(string subControlId, string rawOutput, EvidenceValue typedValue, int durationMs)
    {
        return new Evidence
        {
            EvidenceId = $"{CheckId}-{subControlId}",
            SubControlId = subControlId,
            TechnicalCheckId = CheckId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-ScheduledTask",
            AcquisitionCommand = "Get-ScheduledTask | Where-Object State -ne Disabled | ConvertTo-Json",
            RawOutput = rawOutput.Length > 4000 ? rawOutput.Substring(0, 4000) + "...[truncated]" : rawOutput,
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
            SourceName = "Get-ScheduledTask",
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
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return "[]";

        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        return string.IsNullOrWhiteSpace(output) ? "[]" : output;
    }

    private class TaskInfo
    {
        public string Execute { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public bool IsMicrosoft { get; set; }
        public bool Hidden { get; set; }
        public string TriggerKinds { get; set; } = string.Empty;
    }
}