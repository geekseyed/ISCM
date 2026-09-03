using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Services;

public class FingerprintValidationService : IFingerprintValidationService
{
    private readonly IScanFingerprintGenerator _fingerprintGenerator;

    public FingerprintValidationService(IScanFingerprintGenerator fingerprintGenerator)
    {
        _fingerprintGenerator = fingerprintGenerator ?? throw new ArgumentNullException(nameof(fingerprintGenerator));
    }

    public bool IsEvidenceReused(Evidence evidence, string currentScanId)
    {
        if (evidence == null) return false;
        return evidence.ScanId != currentScanId;
    }

    public bool IsEvidenceStale(Evidence evidence, TimeSpan maxAge)
    {
        if (evidence == null) return true;
        if (evidence.IsInvalidated) return true;

        var age = DateTime.UtcNow - evidence.CollectedAtUtc;
        return age > maxAge;
    }

    public bool CanReuseEvidence(Evidence evidence, string currentScanId, TimeSpan maxAge)
    {
        if (evidence == null) return false;
        if (IsEvidenceReused(evidence, currentScanId)) return false;
        if (IsEvidenceStale(evidence, maxAge)) return false;
        return evidence.IsLive || evidence.IsRemediationGenerated;
    }

    public List<Evidence> DetectReusedEvidence(List<Evidence> evidenceList, string currentScanId)
    {
        if (evidenceList == null) return new List<Evidence>();

        return evidenceList.Where(e => IsEvidenceReused(e, currentScanId)).ToList();
    }

    public void AssignFingerprint(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        evidence.Fingerprint = _fingerprintGenerator.GenerateEvidenceFingerprint(evidence);
    }
}