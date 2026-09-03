using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IRemediationVerificationService
{
    Task<ScanResult> ExecuteRemediationVerificationAsync(string scanId, string subControlId);
    Task<bool> VerifyRemediationSuccessAsync(string scanId, string subControlId);
    IScanContext PrepareVerificationContext(IScanContext originalContext);
    List<Evidence> CollectPostRemediationEvidence(IScanContext context, string subControlId);
}