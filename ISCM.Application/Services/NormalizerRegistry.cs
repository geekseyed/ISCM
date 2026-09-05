using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

/// <summary>
/// Registry for normalizer lookup by (InputType, SourceType) tuple.
/// Mirrors ParserRegistry to keep the normalization boundary consistent.
/// </summary>
public class NormalizerRegistry : INormalizerRegistry
{
    private readonly Dictionary<(Type, EvidenceSourceType), object> _normalizers = new();

    public IEvidenceNormalizer<TInput>? GetNormalizer<TInput>(EvidenceSourceType source)
    {
        var key = (typeof(TInput), source);
        return _normalizers.TryGetValue(key, out var normalizer)
            ? (IEvidenceNormalizer<TInput>)normalizer
            : null;
    }

    public void RegisterNormalizer<TInput>(EvidenceSourceType source, IEvidenceNormalizer<TInput> normalizer)
    {
        if (normalizer == null) throw new ArgumentNullException(nameof(normalizer));
        _normalizers[(typeof(TInput), source)] = normalizer;
    }

    public bool HasNormalizer(EvidenceSourceType source)
    {
        return _normalizers.Keys.Any(k => k.Item2 == source);
    }

    public IEnumerable<EvidenceSourceType> GetRegisteredSources()
    {
        return _normalizers.Keys.Select(k => k.Item2).Distinct();
    }
}