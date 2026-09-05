using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Service for selecting and executing the appropriate parser for a given evidence source.
/// </summary>
public interface IParserService
{
    /// <summary>
    /// Parse raw output using the appropriate parser for the source type.
    /// Returns ParseResult with explicit state (Success/Missing/Invalid/Error).
    /// </summary>
    ParseResult<TOutput> Parse<TInput, TOutput>(TInput input, EvidenceSourceType source);

    /// <summary>
    /// Check if a parser is available for the given source type.
    /// </summary>
    bool HasParser<TInput, TOutput>(EvidenceSourceType source);

    /// <summary>
    /// Get the parser name for logging/debugging.
    /// </summary>
    string? GetParserName<TInput, TOutput>(EvidenceSourceType source);
}