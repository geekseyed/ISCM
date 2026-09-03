using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class EvidenceAcquisitionService : IEvidenceAcquisitionService
{
    private readonly IScanFreshnessPolicy _freshnessPolicy;
    private readonly IEvidenceCacheService _cacheService;

    public EvidenceAcquisitionService(
        IScanFreshnessPolicy freshnessPolicy,
        IEvidenceCacheService cacheService)
    {
        _freshnessPolicy = freshnessPolicy ?? throw new ArgumentNullException(nameof(freshnessPolicy));
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
    }

    public async Task<Evidence> AcquireLiveEvidenceAsync(IScanContext context, string subControlId, string technicalCheckId)
    {
        // Always acquire fresh live evidence for remediation verification and rescan
        var evidence = new Evidence
        {
            ScanId = context.ScanId,
            SubControlId = subControlId,
            TechnicalCheckId = technicalCheckId,
            LifecycleState = EvidenceLifecycleState.Live,
            CollectedAtUtc = DateTime.UtcNow
        };

        // If remediation verification, mark as remediation-generated
        if (context.IsRemediationVerification)
        {
            evidence.MarkAsRemediationGenerated();
        }

        evidence.ComputeFingerprint();
        return evidence;
    }

    public async Task<List<Evidence>> AcquireEvidenceForSubControlAsync(IScanContext context, string subControlId, string technicalCheckId)
    {
        var evidenceList = new List<Evidence>();

        // Always acquire live evidence (fresh scan rules)
        var liveEvidence = await AcquireLiveEvidenceAsync(context, subControlId, technicalCheckId);
        evidenceList.Add(liveEvidence);

        return evidenceList;
    }

    public async Task<Evidence> AcquireRemediationEvidenceAsync(IScanContext context, string subControlId, string technicalCheckId)
    {
        // Remediation verification ALWAYS bypasses cache
        var evidence = new Evidence
        {
            ScanId = context.ScanId,
            SubControlId = subControlId,
            TechnicalCheckId = technicalCheckId,
            LifecycleState = EvidenceLifecycleState.RemediationGenerated,
            CollectedAtUtc = DateTime.UtcNow
        };

        evidence.ComputeFingerprint();
        return evidence;
    }

    public bool ShouldBypassCache(IScanContext context)
    {
        // Remediation verification ALWAYS bypasses cache
        if (context.IsRemediationVerification)
            return true;

        // Rescan ALWAYS bypasses cache
        if (context.IsRescan)
            return true;

        // Normal scan: cache allowed only if explicit contract exists
        return false;
    }
}