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
/// Phase 12.8: Cryptography & TLS Hardening Check (Collector-only pattern).
///
/// Verifies .NET strong cryptography and SCHANNEL protocol configuration.
/// SubControls (8):
///   - CRP-001.1: .NET 4.x SchUseStrongCrypto (64-bit)
///   - CRP-001.2: .NET 4.x SchUseStrongCrypto (32-bit WOW64)
///   - CRP-001.3: TLS 1.2 Client Enabled
///   - CRP-001.4: TLS 1.2 Server Enabled
///   - CRP-001.5: SSL 2.0 Client Disabled (Enabled = 0)
///   - CRP-001.6: SSL 3.0 Client Disabled (Enabled = 0)
///   - CRP-001.7: TLS 1.0 Client Disabled (Enabled = 0)
///   - CRP-001.8: TLS 1.1 Client Disabled (Enabled = 0)
///
/// Note: For "Disabled" checks, registry value 0 means disabled (good),
/// 1 means enabled (bad), and -1 means not configured (Windows default).
/// </summary>
[SupportedOSPlatform("windows")]
public class CryptographyCheck : BaseHardeningCheck
{
    private const string SchannelProtocols = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    public override string CheckId => "CRP-001";
    public override string Name => "Cryptography & TLS Hardening";
    public override CheckCategory Category => CheckCategory.System;
    public override CheckSeverity Severity => CheckSeverity.High;

    private static readonly (string SubControlId, string RegPath, string ValueName)[] Settings =
    {
        // .NET Strong Crypto
        ("CRP-001.1", @"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto"),
        ("CRP-001.2", @"SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto"),

        // TLS 1.2 (should be enabled = 1)
        ("CRP-001.3", $@"{SchannelProtocols}\TLS 1.2\Client", "Enabled"),
        ("CRP-001.4", $@"{SchannelProtocols}\TLS 1.2\Server", "Enabled"),

        // Legacy protocols (should be disabled = 0)
        ("CRP-001.5", $@"{SchannelProtocols}\SSL 2.0\Client", "Enabled"),
        ("CRP-001.6", $@"{SchannelProtocols}\SSL 3.0\Client", "Enabled"),
        ("CRP-001.7", $@"{SchannelProtocols}\TLS 1.0\Client", "Enabled"),
        ("CRP-001.8", $@"{SchannelProtocols}\TLS 1.1\Client", "Enabled")
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

            // -1 indicates "Not Configured" (Windows uses its internal default)
            // 0 = Disabled, 1 = Enabled
            int intValue = value != null ? Convert.ToInt32(value) : -1;
            string rawOutput = value != null ? intValue.ToString() : "Not Configured (-1)";

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