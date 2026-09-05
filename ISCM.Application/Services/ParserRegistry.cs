using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

/// <summary>
/// Registry for parser lookup by EvidenceSourceType.
/// Stores parsers by (InputType, OutputType, SourceType) tuple.
/// </summary>
public class ParserRegistry : IParserRegistry
{
    private readonly Dictionary<(Type, Type, EvidenceSourceType), object> _parsers = new();

    public IParser<TInput, TOutput>? GetParser<TInput, TOutput>(EvidenceSourceType source)
    {
        var key = (typeof(TInput), typeof(TOutput), source);
        return _parsers.TryGetValue(key, out var parser) ? (IParser<TInput, TOutput>)parser : null;
    }

    public void RegisterParser<TInput, TOutput>(EvidenceSourceType source, IParser<TInput, TOutput> parser)
    {
        if (parser == null) throw new ArgumentNullException(nameof(parser));
        var key = (typeof(TInput), typeof(TOutput), source);
        _parsers[key] = parser;
    }

    public bool HasParser(EvidenceSourceType source)
    {
        return _parsers.Keys.Any(k => k.Item3 == source);
    }

    public IEnumerable<EvidenceSourceType> GetRegisteredSources()
    {
        return _parsers.Keys.Select(k => k.Item3).Distinct();
    }
}