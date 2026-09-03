using System.Security.Cryptography;
using System.Text;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Services;

public class EvidenceFingerprintGenerator : IEvidenceFingerprintGenerator
{
    public string GenerateFingerprint(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));

        var data = $"{evidence.EvidenceId}|{evidence.ScanId}|{evidence.SourceType}|{evidence.SourceName}|{evidence.ParsedValue}|{evidence.CollectedAtUtc:O}";
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(bytes);
    }

    public bool ValidateFingerprint(Evidence evidence, string expectedFingerprint)
    {
        var actual = GenerateFingerprint(evidence);
        return string.Equals(actual, expectedFingerprint, StringComparison.Ordinal);
    }
}