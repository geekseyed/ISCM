using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IEvidenceCacheService
{
    Evidence? GetCachedEvidence(string scanId, string subControlId);
    void CacheEvidence(Evidence evidence);
    void InvalidateEvidence(string scanId, string subControlId);
    void InvalidateAllEvidence(string scanId);
    void InvalidateBySource(string sourceName);
    bool IsEvidenceFresh(Evidence evidence, TimeSpan maxAge);
}