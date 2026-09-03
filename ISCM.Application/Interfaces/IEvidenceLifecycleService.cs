using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IEvidenceLifecycleService
{
    void MarkAsCached(Evidence evidence);
    void MarkAsHistorical(Evidence evidence);
    void MarkAsRemediationGenerated(Evidence evidence);
    void Invalidate(Evidence evidence);
    bool IsFresh(Evidence evidence, TimeSpan maxAge);
    bool IsFresh(Evidence evidence);
    bool CanUseForEvaluation(Evidence evidence);
    List<Evidence> FilterUsable(List<Evidence> evidenceList);
}