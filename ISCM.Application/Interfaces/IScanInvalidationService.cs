using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IScanInvalidationService
{
    void InvalidateForRemediation(string scanId, string subControlId);
    void InvalidateAllForScan(string scanId);
    void InvalidateDependentEvidence(string scanId, string sourceName);
    IScanContext CreateNewScanContext(IScanContext previousContext);
    List<Evidence> GetInvalidatedEvidence(string scanId, string subControlId);
}