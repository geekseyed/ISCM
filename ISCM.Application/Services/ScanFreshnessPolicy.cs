using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class ScanFreshnessPolicy : IScanFreshnessPolicy
{
    private readonly IEvidenceLifecycleService _lifecycleService;

    public ScanFreshnessPolicy(IEvidenceLifecycleService lifecycleService)
    {
        _lifecycleService = lifecycleService ?? throw new ArgumentNullException(nameof(lifecycleService));
    }

    public bool ShouldAcquireLiveEvidence(IScanContext context, string subControlId)
    {
        // Remediation verification ALWAYS requires fresh live evidence
        if (context.IsRemediationVerification)
            return true;

        // Rescan requires fresh live evidence
        if (context.IsRescan)
            return true;

        // Normal scan requires live evidence (no cache by default)
        return true;
    }

    public bool CanUseCachedEvidence(IScanContext context, Evidence evidence)
    {
        if (evidence == null) return false;
        if (evidence.IsInvalidated) return false;

        // Remediation verification NEVER uses cached evidence
        if (context.IsRemediationVerification)
            return false;

        // Rescan NEVER uses cached evidence
        if (context.IsRescan)
            return false;

        // Normal scan: only allow cached if explicit cache contract exists
        return evidence.IsCached && _lifecycleService.IsFresh(evidence);
    }

    public void ValidateEvidenceFreshness(IScanContext context, List<Evidence> evidenceList)
    {
        if (evidenceList == null) return;

        foreach (var evidence in evidenceList)
        {
            if (context.IsRemediationVerification || context.IsRescan)
            {
                // For remediation/rescan, only live or remediation-generated evidence allowed
                if (!evidence.IsLive && !evidence.IsRemediationGenerated)
                {
                    evidence.Invalidate();
                }
            }
        }
    }

    public List<Evidence> FilterEvidenceForEvaluation(IScanContext context, List<Evidence> evidenceList)
    {
        if (evidenceList == null) return new List<Evidence>();

        ValidateEvidenceFreshness(context, evidenceList);

        return evidenceList.Where(e =>
        {
            if (context.IsRemediationVerification || context.IsRescan)
                return e.IsLive || e.IsRemediationGenerated;

            return e.IsUsable && _lifecycleService.IsFresh(e);
        }).ToList();
    }
}