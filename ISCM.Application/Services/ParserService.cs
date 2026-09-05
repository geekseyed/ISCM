using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Services;

/// <summary>
/// Service for selecting and executing the appropriate parser.
/// Falls back to EvidenceSourceType.Other if specific parser not found.
/// </summary>
public class ParserService : IParserService
{
    private readonly IParserRegistry _registry;

    public ParserService(IParserRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public ParseResult<TOutput> Parse<TInput, TOutput>(TInput input, EvidenceSourceType source)
    {
        if (input == null)
        {
            return ParseResult<TOutput>.Missing("Input is null", null);
        }

        // Try exact source type first
        var parser = _registry.GetParser<TInput, TOutput>(source);

        // Fallback to Other if specific parser not found
        if (parser == null && source != EvidenceSourceType.Other)
        {
            parser = _registry.GetParser<TInput, TOutput>(EvidenceSourceType.Other);
        }

        if (parser == null)
        {
            return ParseResult<TOutput>.Failure(
                ParseErrorCode.UnexpectedError,
                $"No parser registered for source type {source}",
                input?.ToString());
        }

        return parser.Parse(input);
    }

    public bool HasParser<TInput, TOutput>(EvidenceSourceType source)
    {
        var parser = _registry.GetParser<TInput, TOutput>(source);
        if (parser != null) return true;

        // Check fallback
        if (source != EvidenceSourceType.Other)
        {
            parser = _registry.GetParser<TInput, TOutput>(EvidenceSourceType.Other);
        }

        return parser != null;
    }

    public string? GetParserName<TInput, TOutput>(EvidenceSourceType source)
    {
        var parser = _registry.GetParser<TInput, TOutput>(source);
        if (parser == null && source != EvidenceSourceType.Other)
        {
            parser = _registry.GetParser<TInput, TOutput>(EvidenceSourceType.Other);
        }

        return parser?.Name;
    }
}