using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IScanFreshnessPolicy
{
    bool ShouldAcquireLiveEvidence(IScanContext context, string subControlId);
    bool CanUseCachedEvidence(IScanContext context, Evidence evidence);
    void ValidateEvidenceFreshness(IScanContext context, List<Evidence> evidenceList);
    List<Evidence> FilterEvidenceForEvaluation(IScanContext context, List<Evidence> evidenceList);
}