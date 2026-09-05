using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Interfaces;

/// <summary>
/// End-to-end normalization pipeline: raw output → parser → normalizer → EvidenceValue.
/// This is the ONLY entry point the scanner uses to produce typed evidence values.
/// </summary>
public interface INormalizationService
{
    /// <summary>
    /// Parse and normalize raw output for a given evidence source type.
    /// Returns ParseResult<EvidenceValue> with explicit states.
    /// </summary>
    ParseResult<EvidenceValue> NormalizeRaw(string rawOutput, EvidenceSourceType source);

    /// <summary>
    /// Check if a parser+normalizer pipeline exists for the given source type.
    /// </summary>
    bool CanNormalize(EvidenceSourceType source);
}