using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Services;

/// <summary>
/// End-to-end pipeline: raw output → IParser → IEvidenceNormalizer → EvidenceValue.
/// 
/// Routes by EvidenceSourceType:
///   Registry    → RegistryParser    → RegistryNormalizer
///   Secedit     → SeceditParser     → SeceditNormalizer
///   NetAccounts → NetAccountsParser → NetAccountsNormalizer
///   Auditpol    → AuditpolParser    → AuditpolNormalizer
///   PowerShell  → PowerShellParser  → PowerShellNormalizer
///   Other       → PowerShellParser  → PowerShellNormalizer (general command output)
/// 
/// Failed states propagate explicitly - raw output never leaks into typed evaluation.
/// </summary>
public class NormalizationService : INormalizationService
{
    private readonly IParserRegistry _parserRegistry;
    private readonly INormalizerRegistry _normalizerRegistry;

    public NormalizationService(IParserRegistry parserRegistry, INormalizerRegistry normalizerRegistry)
    {
        _parserRegistry = parserRegistry ?? throw new ArgumentNullException(nameof(parserRegistry));
        _normalizerRegistry = normalizerRegistry ?? throw new ArgumentNullException(nameof(normalizerRegistry));
    }

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source switch
        {
            EvidenceSourceType.Registry => HasPipeline<RegistryValueData>(source),
            EvidenceSourceType.Secedit => HasPipeline<SeceditPolicyData>(source),
            EvidenceSourceType.NetAccounts => HasPipeline<NetAccountsData>(source),
            EvidenceSourceType.Auditpol => HasPipeline<AuditpolData>(source),
            EvidenceSourceType.PowerShell => HasPipeline<PowerShellData>(source),
            _ => HasPipeline<PowerShellData>(EvidenceSourceType.PowerShell)
        };
    }

    public ParseResult<EvidenceValue> NormalizeRaw(string rawOutput, EvidenceSourceType source)
    {
        return source switch
        {
            EvidenceSourceType.Registry =>
                RunPipeline<RegistryValueData>(rawOutput, source),

            EvidenceSourceType.Secedit =>
                RunPipeline<SeceditPolicyData>(rawOutput, source),

            EvidenceSourceType.NetAccounts =>
                RunPipeline<NetAccountsData>(rawOutput, source),

            EvidenceSourceType.Auditpol =>
                RunPipeline<AuditpolData>(rawOutput, source),

            EvidenceSourceType.PowerShell =>
                RunPipeline<PowerShellData>(rawOutput, source),

            // General command output falls back to PowerShell pipeline
            _ => RunPipeline<PowerShellData>(rawOutput, EvidenceSourceType.PowerShell)
        };
    }

    // === PRIVATE ===

    private ParseResult<EvidenceValue> RunPipeline<TParsed>(string rawOutput, EvidenceSourceType source)
    {
        var parser = _parserRegistry.GetParser<string, TParsed>(source);

        // Fallback parser lookup for Other
        if (parser == null && source != EvidenceSourceType.Other)
        {
            parser = _parserRegistry.GetParser<string, TParsed>(EvidenceSourceType.Other);
        }

        if (parser == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"No parser registered for source type {source}",
                rawOutput);
        }

        var parseResult = parser.Parse(rawOutput);

        var normalizer = _normalizerRegistry.GetNormalizer<TParsed>(source);

        if (normalizer == null && source != EvidenceSourceType.Other)
        {
            normalizer = _normalizerRegistry.GetNormalizer<TParsed>(EvidenceSourceType.PowerShell);
        }

        if (normalizer == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                $"No normalizer registered for source type {source}",
                rawOutput);
        }

        return normalizer.Normalize(parseResult);
    }

    private bool HasPipeline<TParsed>(EvidenceSourceType source)
    {
        var parser = _parserRegistry.GetParser<string, TParsed>(source);
        var normalizer = _normalizerRegistry.GetNormalizer<TParsed>(source);
        return parser != null && normalizer != null;
    }
}