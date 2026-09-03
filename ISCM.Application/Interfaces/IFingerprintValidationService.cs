using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IFingerprintValidationService
{
    bool IsEvidenceReused(Evidence evidence, string currentScanId);
    bool IsEvidenceStale(Evidence evidence, TimeSpan maxAge);
    bool CanReuseEvidence(Evidence evidence, string currentScanId, TimeSpan maxAge);
    List<Evidence> DetectReusedEvidence(List<Evidence> evidenceList, string currentScanId);
    void AssignFingerprint(Evidence evidence);
}