using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IScanFingerprintGenerator
{
    string GenerateScanFingerprint(ScanResult scanResult);
    string GenerateEvidenceFingerprint(Evidence evidence);
    bool ValidateScanFingerprint(ScanResult scanResult, string expectedFingerprint);
    bool ValidateEvidenceFingerprint(Evidence evidence, string expectedFingerprint);
}