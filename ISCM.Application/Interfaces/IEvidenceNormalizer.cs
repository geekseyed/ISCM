using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Normalization contract: ParseResult<TInput> → ParseResult<EvidenceValue>
/// 
/// The normalizer is the ONLY place where parsed data becomes a typed
/// EvidenceValue for evaluation. Evaluation code MUST NOT consume raw
/// strings or ParseResult<T> directly.
/// 
/// Rules:
///   - If parseResult is not Success, propagate the same state (Missing/Invalid/Error)
///   - NEVER fabricate a default EvidenceValue from failed input
///   - Conversion MUST be type-preserving (no lossy conversion)
/// </summary>
public interface IEvidenceNormalizer<TInput>
{
    /// <summary>
    /// Normalizer unique name (e.g., "RegistryNormalizer")
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Evidence source this normalizer handles
    /// </summary>
    EvidenceSourceType SourceType { get; }

    /// <summary>
    /// Check if this normalizer can handle the given source type
    /// </summary>
    bool CanNormalize(EvidenceSourceType source);

    /// <summary>
    /// Convert a successful parse result into a typed EvidenceValue.
    /// Failed parse states are propagated explicitly.
    /// </summary>
    ParseResult<EvidenceValue> Normalize(ParseResult<TInput> parseResult);
}