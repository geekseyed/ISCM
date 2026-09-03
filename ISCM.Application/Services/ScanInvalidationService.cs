using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class ScanInvalidationService : IScanInvalidationService
{
    private readonly IEvidenceCacheService _cacheService;
    private readonly IEvidenceLifecycleService _lifecycleService;

    public ScanInvalidationService(
        IEvidenceCacheService cacheService,
        IEvidenceLifecycleService lifecycleService)
    {
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
        _lifecycleService = lifecycleService ?? throw new ArgumentNullException(nameof(lifecycleService));
    }

    public void InvalidateForRemediation(string scanId, string subControlId)
    {
        // Invalidate specific evidence for this subcontrol
        _cacheService.InvalidateEvidence(scanId, subControlId);
    }

    public void InvalidateAllForScan(string scanId)
    {
        // Invalidate all evidence associated with this scan
        _cacheService.InvalidateAllEvidence(scanId);
    }

    public void InvalidateDependentEvidence(string scanId, string sourceName)
    {
        // Invalidate evidence from a specific source
        _cacheService.InvalidateBySource(sourceName);
    }

    public IScanContext CreateNewScanContext(IScanContext previousContext)
    {
        if (previousContext == null) throw new ArgumentNullException(nameof(previousContext));

        // Create new scan context with new ScanId
        var newMode = previousContext.IsRemediationVerification
            ? ScanMode.RemediationVerification
            : ScanMode.Rescan;

        return new ScanContext(
            previousContext.TargetId,
            newMode,
            previousContext.ScannerVersion
        );
    }

    public List<Evidence> GetInvalidatedEvidence(string scanId, string subControlId)
    {
        // Return invalidated evidence for auditing
        var cached = _cacheService.GetCachedEvidence(scanId, subControlId);
        if (cached != null && cached.IsInvalidated)
        {
            return new List<Evidence> { cached };
        }
        return new List<Evidence>();
    }
}