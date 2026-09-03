using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IEvidenceAcquisitionService
{
    Task<Evidence> AcquireLiveEvidenceAsync(IScanContext context, string subControlId, string technicalCheckId);
    Task<List<Evidence>> AcquireEvidenceForSubControlAsync(IScanContext context, string subControlId, string technicalCheckId);
    Task<Evidence> AcquireRemediationEvidenceAsync(IScanContext context, string subControlId, string technicalCheckId);
    bool ShouldBypassCache(IScanContext context);
}