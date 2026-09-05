using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Registry for normalizer lookup by EvidenceSourceType.
/// Mirrors IParserRegistry to keep the normalization boundary consistent.
/// </summary>
public interface INormalizerRegistry
{
    /// <summary>
    /// Get normalizer for a specific input type and evidence source.
    /// Returns null if no normalizer is registered.
    /// </summary>
    IEvidenceNormalizer<TInput>? GetNormalizer<TInput>(EvidenceSourceType source);

    /// <summary>
    /// Register a normalizer for a specific input type and evidence source.
    /// </summary>
    void RegisterNormalizer<TInput>(EvidenceSourceType source, IEvidenceNormalizer<TInput> normalizer);

    /// <summary>
    /// Check if a normalizer is registered for the given source.
    /// </summary>
    bool HasNormalizer(EvidenceSourceType source);

    /// <summary>
    /// Get all registered evidence source types.
    /// </summary>
    IEnumerable<EvidenceSourceType> GetRegisteredSources();
}