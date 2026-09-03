using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Generic parser contract: Raw Input → ParseResult<T>
/// Every parser MUST return ParseResult<T> with explicit state.
/// </summary>
public interface IParser<TInput, TOutput>
{
    /// <summary>
    /// Parser unique name (e.g., "RegistryParser", "SeceditParser")
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Parser version for tracking and debugging
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Evidence sources this parser can handle
    /// </summary>
    IEnumerable<EvidenceSourceType> SupportedSources { get; }

    /// <summary>
    /// Check if this parser can handle the given evidence source type
    /// </summary>
    bool CanParse(EvidenceSourceType source);

    /// <summary>
    /// Parse raw input and return explicit ParseResult
    /// MUST NOT throw exceptions for expected error states (Missing, Invalid)
    /// Only throw for unexpected/programming errors
    /// </summary>
    ParseResult<TOutput> Parse(TInput input);

    /// <summary>
    /// Async version of Parse
    /// </summary>
    Task<ParseResult<TOutput>> ParseAsync(TInput input);
}