using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Normalizers;

/// <summary>
/// Converts ParseResult<AuditpolData> into ParseResult<EvidenceValue>.
/// 
/// Lookup uses EXACT normalized subcategory matching (BUG-05 safe):
/// "Logon" is NEVER confused with "Logoff".
/// 
/// Three modes:
///   1. Normalize(...)            → whole data as StructuredObject
///   2. NormalizeSetting(...)     → setting string as Enum-typed EvidenceValue
///   3. NormalizeAuditFlag(...)   → Success/Failure audit as Boolean EvidenceValue
/// 
/// Propagation rules:
///   - Missing/Invalid/Error parse states propagate explicitly
///   - Missing category/subcategory → Missing (never fabricated)
///   - No silent defaults
/// </summary>
public class AuditpolNormalizer : IEvidenceNormalizer<AuditpolData>
{
    public string Name => "AuditpolNormalizer";

    public EvidenceSourceType SourceType => EvidenceSourceType.Auditpol;

    public bool CanNormalize(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Auditpol
            || source == EvidenceSourceType.Other;
    }

    /// <summary>
    /// Convert the entire parsed data into a StructuredObject EvidenceValue.
    /// </summary>
    public ParseResult<EvidenceValue> Normalize(ParseResult<AuditpolData> parseResult)
    {
        if (parseResult == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is null");
        }

        var failed = PropagateFailedState(parseResult);
        if (failed != null) return failed;

        if (parseResult.Value == null)
        {
            return ParseResult<EvidenceValue>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is Success but Value is null",
                parseResult.RawInput);
        }

        return ParseResult<EvidenceValue>.Success(
            new EvidenceValue(
                value: parseResult.Value,
                type: EvidenceValueType.StructuredObject,
                unit: null,
                rawString: parseResult.Value.ToString()),
            parseResult.RawInput);
    }

    /// <summary>
    /// Extract the raw setting of a subcategory as an Enum-typed EvidenceValue.
    /// Example: "Success and Failure", "Success", "Failure", "No Auditing".
    /// </summary>
    public ParseResult<EvidenceValue> NormalizeSetting(
        ParseResult<AuditpolData> parseResult,
        string category,
        string subcategory)
    {
        var entryResult = ResolveEntry(parseResult, category, subcategory);
        if (!entryResult.IsSuccess || entryResult.Value == null)
        {
            return PropagateEntryFailure(entryResult);
        }

        var entry = entryResult.Value;

        return ParseResult<EvidenceValue>.Success(
            new EvidenceValue(
                value: entry.SettingRaw,
                type: EvidenceValueType.Enum,
                unit: null,
                rawString: entry.SettingRaw),
            parseResult.RawInput);
    }

    /// <summary>
    /// Extract Success or Failure audit flag as a Boolean EvidenceValue.
    /// This is the primary method used by evaluation logic.
    /// </summary>
    /// <param name="auditSuccess">true → AuditSuccess flag, false → AuditFailure flag</param>
    public ParseResult<EvidenceValue> NormalizeAuditFlag(
        ParseResult<AuditpolData> parseResult,
        string category,
        string subcategory,
        bool auditSuccess)
    {
        var entryResult = ResolveEntry(parseResult, category, subcategory);
        if (!entryResult.IsSuccess || entryResult.Value == null)
        {
            return PropagateEntryFailure(entryResult);
        }

        var entry = entryResult.Value;
        var flagValue = auditSuccess ? entry.AuditSuccess : entry.AuditFailure;

        return ParseResult<EvidenceValue>.Success(
            EvidenceValue.FromBoolean(flagValue),
            parseResult.RawInput);
    }

    /// <summary>
    /// Resolve a subcategory entry using EXACT normalized matching.
    /// Returns Missing if category or subcategory does not exist.
    /// </summary>
    private ParseResult<AuditpolEntry> ResolveEntry(
        ParseResult<AuditpolData> parseResult,
        string category,
        string subcategory)
    {
        if (parseResult == null)
        {
            return ParseResult<AuditpolEntry>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is null");
        }

        if (parseResult.IsMissing)
        {
            return ParseResult<AuditpolEntry>.Missing(
                parseResult.Error?.Message ?? "auditpol output is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<AuditpolEntry>.Invalid(
                parseResult.Error?.Message ?? "auditpol output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<AuditpolEntry>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "auditpol parse failed",
                parseResult.RawInput);
        }

        var data = parseResult.Value;
        if (data == null)
        {
            return ParseResult<AuditpolEntry>.Failure(
                ParseErrorCode.UnexpectedError,
                "parseResult is Success but Value is null",
                parseResult.RawInput);
        }

        // Missing category → Missing
        if (!data.GetEntriesInCategory(category).Any())
        {
            return ParseResult<AuditpolEntry>.Missing(
                $"Category '{category}' not found in auditpol output",
                parseResult.RawInput);
        }

        // Missing subcategory (EXACT match) → Missing
        if (!data.HasSubcategory(category, subcategory))
        {
            return ParseResult<AuditpolEntry>.Missing(
                $"Subcategory '{subcategory}' not found in category '{category}'",
                parseResult.RawInput);
        }

        return ParseResult<AuditpolEntry>.Success(
            data.GetEntry(category, subcategory)!,
            parseResult.RawInput);
    }

    /// <summary>
    /// Convert a failed ParseResult<AuditpolEntry> into ParseResult<EvidenceValue>.
    /// ParseResult<T> is invariant, so failed states must be propagated explicitly.
    /// </summary>
    private static ParseResult<EvidenceValue> PropagateEntryFailure(
        ParseResult<AuditpolEntry> entryResult)
    {
        if (entryResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                entryResult.Error?.Message ?? "auditpol entry is missing",
                entryResult.RawInput);
        }

        if (entryResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                entryResult.Error?.Message ?? "auditpol entry is invalid",
                entryResult.RawInput);
        }

        return ParseResult<EvidenceValue>.Failure(
            entryResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
            entryResult.Error?.Message ?? "auditpol entry resolution failed",
            entryResult.RawInput);
    }

    /// <summary>
    /// Returns a failed ParseResult if the input parse state is not Success, else null.
    /// </summary>
    private static ParseResult<EvidenceValue>? PropagateFailedState(
        ParseResult<AuditpolData> parseResult)
    {
        if (parseResult.IsMissing)
        {
            return ParseResult<EvidenceValue>.Missing(
                parseResult.Error?.Message ?? "auditpol output is missing",
                parseResult.RawInput);
        }

        if (parseResult.IsInvalid)
        {
            return ParseResult<EvidenceValue>.Invalid(
                parseResult.Error?.Message ?? "auditpol output is invalid",
                parseResult.RawInput);
        }

        if (parseResult.IsError)
        {
            return ParseResult<EvidenceValue>.Failure(
                parseResult.Error?.Code ?? ParseErrorCode.UnexpectedError,
                parseResult.Error?.Message ?? "auditpol parse failed",
                parseResult.RawInput);
        }

        return null;
    }
}