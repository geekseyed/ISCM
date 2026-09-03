using System.Collections.Concurrent;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class EvidenceCacheService : IEvidenceCacheService
{
    private readonly ConcurrentDictionary<string, Evidence> _cache = new();

    public Evidence? GetCachedEvidence(string scanId, string subControlId)
    {
        var key = $"{scanId}:{subControlId}";
        return _cache.TryGetValue(key, out var evidence) ? evidence : null;
    }

    public void CacheEvidence(Evidence evidence)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));

        var key = $"{evidence.ScanId}:{evidence.SubControlId}";
        evidence.LifecycleState = EvidenceLifecycleState.Cached;
        _cache[key] = evidence;
    }

    public void InvalidateEvidence(string scanId, string subControlId)
    {
        var key = $"{scanId}:{subControlId}";
        if (_cache.TryRemove(key, out var evidence))
        {
            evidence.Invalidate();
        }
    }

    public void InvalidateAllEvidence(string scanId)
    {
        var keysToRemove = _cache.Keys.Where(k => k.StartsWith($"{scanId}:")).ToList();
        foreach (var key in keysToRemove)
        {
            if (_cache.TryRemove(key, out var evidence))
            {
                evidence.Invalidate();
            }
        }
    }

    public void InvalidateBySource(string sourceName)
    {
        var keysToRemove = _cache.Keys.Where(k =>
            _cache.TryGetValue(k, out var ev) && ev.SourceName == sourceName).ToList();

        foreach (var key in keysToRemove)
        {
            if (_cache.TryRemove(key, out var evidence))
            {
                evidence.Invalidate();
            }
        }
    }

    public bool IsEvidenceFresh(Evidence evidence, TimeSpan maxAge)
    {
        if (evidence == null) return false;
        if (evidence.LifecycleState == EvidenceLifecycleState.Invalidated) return false;

        var age = DateTime.UtcNow - evidence.CollectedAtUtc;
        return age <= maxAge;
    }
}