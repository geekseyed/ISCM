using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Registry for parser lookup by EvidenceSourceType
/// Enables dynamic parser selection based on evidence source
/// </summary>
public interface IParserRegistry
{
    /// <summary>
    /// Get parser for a specific input/output type and evidence source
    /// Returns null if no parser is registered
    /// </summary>
    IParser<TInput, TOutput>? GetParser<TInput, TOutput>(EvidenceSourceType source);

    /// <summary>
    /// Register a parser for a specific input/output type and evidence source
    /// </summary>
    void RegisterParser<TInput, TOutput>(EvidenceSourceType source, IParser<TInput, TOutput> parser);

    /// <summary>
    /// Check if a parser is registered for the given source
    /// </summary>
    bool HasParser(EvidenceSourceType source);

    /// <summary>
    /// Get all registered evidence source types
    /// </summary>
    IEnumerable<EvidenceSourceType> GetRegisteredSources();
}