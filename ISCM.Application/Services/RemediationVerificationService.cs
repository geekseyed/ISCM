using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class RemediationVerificationService : IRemediationVerificationService
{
    private readonly IScanInvalidationService _invalidationService;
    private readonly IEvidenceAcquisitionService _acquisitionService;
    private readonly IScanFreshnessPolicy _freshnessPolicy;

    public RemediationVerificationService(
        IScanInvalidationService invalidationService,
        IEvidenceAcquisitionService acquisitionService,
        IScanFreshnessPolicy freshnessPolicy)
    {
        _invalidationService = invalidationService ?? throw new ArgumentNullException(nameof(invalidationService));
        _acquisitionService = acquisitionService ?? throw new ArgumentNullException(nameof(acquisitionService));
        _freshnessPolicy = freshnessPolicy ?? throw new ArgumentNullException(nameof(freshnessPolicy));
    }

    public async Task<ScanResult> ExecuteRemediationVerificationAsync(string scanId, string subControlId)
    {
        // Step 1: Invalidate old evidence
        _invalidationService.InvalidateForRemediation(scanId, subControlId);

        // Step 2: Create new scan context with new ScanId
        var newContext = new ScanContext(
            targetId: subControlId,
            mode: ScanMode.RemediationVerification
        );

        // Step 3: Acquire fresh evidence (bypass cache)
        var evidence = await _acquisitionService.AcquireLiveEvidenceAsync(newContext, subControlId, subControlId);

        // Step 4: Create new scan result
        var scanResult = new ScanResult
        {
            ScanId = newContext.ScanId,
            TargetId = subControlId,
            Mode = ScanMode.RemediationVerification,
            StartedAtUtc = DateTime.UtcNow
        };

        return scanResult;
    }

    public async Task<bool> VerifyRemediationSuccessAsync(string scanId, string subControlId)
    {
        var context = new ScanContext(
            targetId: subControlId,
            mode: ScanMode.RemediationVerification
        );

        var evidence = await _acquisitionService.AcquireLiveEvidenceAsync(context, subControlId, subControlId);

        // Success if evidence is live and not invalidated
        return evidence.IsLive && !evidence.IsInvalidated;
    }

    public IScanContext PrepareVerificationContext(IScanContext originalContext)
    {
        return _invalidationService.CreateNewScanContext(originalContext);
    }

    public List<Evidence> CollectPostRemediationEvidence(IScanContext context, string subControlId)
    {
        var evidence = _acquisitionService.AcquireLiveEvidenceAsync(context, subControlId, subControlId).Result;
        return new List<Evidence> { evidence };
    }
}