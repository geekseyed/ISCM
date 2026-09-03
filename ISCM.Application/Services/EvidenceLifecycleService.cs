using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Services;

public class EvidenceLifecycleService : IEvidenceLifecycleService
{
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(30);

    public void MarkAsCached(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        evidence.MarkAsCached();
    }

    public void MarkAsHistorical(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        evidence.MarkAsHistorical();
    }

    public void MarkAsRemediationGenerated(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        evidence.MarkAsRemediationGenerated();
    }

    public void Invalidate(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        evidence.Invalidate();
    }

    public bool IsFresh(Evidence evidence, TimeSpan maxAge)
    {
        if (evidence == null) return false;
        if (evidence.IsInvalidated) return false;

        var age = DateTime.UtcNow - evidence.CollectedAtUtc;
        return age <= maxAge;
    }

    public bool IsFresh(Evidence evidence)
    {
        return IsFresh(evidence, DefaultMaxAge);
    }

    public bool CanUseForEvaluation(Evidence evidence)
    {
        if (evidence == null) return false;
        return evidence.IsUsable && IsFresh(evidence);
    }

    public List<Evidence> FilterUsable(List<Evidence> evidenceList)
    {
        if (evidenceList == null) return new List<Evidence>();
        return evidenceList.Where(e => CanUseForEvaluation(e)).ToList();
    }
}