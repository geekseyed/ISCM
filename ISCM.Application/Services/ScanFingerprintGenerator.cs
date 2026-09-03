using System.Security.Cryptography;
using System.Text;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Services;

public class ScanFingerprintGenerator : IScanFingerprintGenerator
{
    public string GenerateScanFingerprint(ScanResult scanResult)
    {
        if (scanResult == null) throw new ArgumentNullException(nameof(scanResult));

        var content = $"{scanResult.ScanId}|{scanResult.TargetId}|{scanResult.Mode}|{scanResult.StartedAtUtc:O}|{scanResult.ScannerVersion}";
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
        return Convert.ToBase64String(bytes);
    }

    public string GenerateEvidenceFingerprint(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));

        var content = $"{evidence.EvidenceId}|{evidence.ScanId}|{evidence.SubControlId}|{evidence.PathId}|{evidence.SourceType}|{evidence.SourceName}|{evidence.NormalizedValue}|{evidence.CollectedAtUtc:O}";
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
        return Convert.ToBase64String(bytes);
    }

    public bool ValidateScanFingerprint(ScanResult scanResult, string expectedFingerprint)
    {
        var actual = GenerateScanFingerprint(scanResult);
        return string.Equals(actual, expectedFingerprint, StringComparison.Ordinal);
    }

    public bool ValidateEvidenceFingerprint(Evidence evidence, string expectedFingerprint)
    {
        var actual = GenerateEvidenceFingerprint(evidence);
        return string.Equals(actual, expectedFingerprint, StringComparison.Ordinal);
    }
}