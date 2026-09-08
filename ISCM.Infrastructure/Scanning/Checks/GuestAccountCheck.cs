using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
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
/// Phase 10.6: Guest Account Check (Collector-only pattern).
/// 
/// این چک **فقط Collector** است:
/// - Evidence تولید می‌کند (RawOutput + TypedValue)
/// - Evidence.Evaluation = NotScanned (ارزیابی نمی‌کند)
/// - Scanner مسئول ارزیابی تایپ‌شده با استفاده از کاتالوگ است
/// 
/// SubControls:
///   - GUEST-001.1: Guest account status (Boolean, Equals, Disabled)
///   - GUEST-001.2: Rename guest account (String, NotEquals, "Guest")
/// </summary>
[SupportedOSPlatform("windows")]
public class GuestAccountCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    public override string CheckId => "GUEST-001";
    public override string Name => "Guest Account";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.Critical;

    public GuestAccountCheck()
    {
        _registryParser = new RegistryParser();
    }

    /// <summary>
    /// Phase 10.6: Collects evidence for both guest account SubControls.
    /// </summary>
    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        evidenceList.Add(await CollectGuestAccountStatus());
        evidenceList.Add(await CollectGuestAccountRename());

        return evidenceList;
    }

    private async Task<Evidence> CollectGuestAccountStatus()
    {
        var subControlId = "GUEST-001.1";
        var startTime = DateTime.UtcNow;

        try
        {
            // Use PowerShell to get Guest account status by SID (works even if renamed)
            var rawOutput = await RunPowerShellAsync(
                "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -ExpandProperty Enabled");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var typedValue = ExtractGuestStatusFromOutput(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-LocalUser (SID -501)",
                AcquisitionCommand = "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -ExpandProperty Enabled",
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

    private async Task<Evidence> CollectGuestAccountRename()
    {
        var subControlId = "GUEST-001.2";
        var startTime = DateTime.UtcNow;

        try
        {
            // Use PowerShell to get SID -501 account name
            var rawOutput = await RunPowerShellAsync(
                "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -ExpandProperty Name");

            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var typedValue = ExtractGuestNameFromOutput(rawOutput);

            return new Evidence
            {
                EvidenceId = $"{CheckId}-{subControlId}",
                SubControlId = subControlId,
                SourceType = EvidenceSourceType.PowerShell,
                SourceName = "Get-LocalUser (SID -501)",
                AcquisitionCommand = "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -ExpandProperty Name",
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

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        return new Evidence
        {
            EvidenceId = $"GUEST-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.PowerShell,
            SourceName = "Get-LocalUser",
            RawOutput = ex.Message,
            TypedValue = null,
            Evaluation = CheckStatus.Error,
            Error = ex.Message,
            CollectedAtUtc = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Extracts Guest account enabled state as Boolean.
    /// 
    /// PowerShell Get-LocalUser ... Enabled returns:
    ///   "True"  → account is ENABLED  → Boolean true
    ///   "False" → account is DISABLED → Boolean false
    /// 
    /// Catalog expects "Disabled" which parses to Boolean false,
    /// so actual must mirror the raw enabled flag (NO inversion).
    /// 
    /// Phase 10.6 fix: removed incorrect inversion that caused
    /// disabled accounts to fail the "Disabled" expectation.
    /// </summary>
    private static EvidenceValue ExtractGuestStatusFromOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            // Conservative: unknown → assume enabled (insecure) so check fails safely
            return EvidenceValue.FromBoolean(true);

        var trimmed = rawOutput.Trim();

        // Account DISABLED → Boolean false (matches catalog "Disabled")
        if (trimmed.Equals("False", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("No", StringComparison.OrdinalIgnoreCase))
        {
            return EvidenceValue.FromBoolean(false);
        }

        // Account ENABLED → Boolean true (will fail "Disabled" expectation)
        if (trimmed.Equals("True", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("Yes", StringComparison.OrdinalIgnoreCase))
        {
            return EvidenceValue.FromBoolean(true);
        }

        // Conservative fallback: assume enabled
        return EvidenceValue.FromBoolean(true);
    }

    /// <summary>
    /// Extracts the Guest account name from PowerShell output.
    /// The value is compared against "Guest" in catalog with NotEquals operator.
    /// </summary>
    private static EvidenceValue ExtractGuestNameFromOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return EvidenceValue.FromString("(unknown)");

        var trimmed = rawOutput.Trim();

        // PowerShell may output multiple lines or just the name
        var firstLine = trimmed.Split('\n')[0].Trim();

        // Remove any PowerShell formatting artifacts
        if (firstLine.StartsWith("---"))
            return EvidenceValue.FromString("(unknown)");

        return EvidenceValue.FromString(firstLine);
    }

    private static async Task<string> RunPowerShellAsync(string command)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-Command \"{command}\"")
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