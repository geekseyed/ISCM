using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses `auditpol /get /category:*` output into structured AuditpolData.
/// 
/// Uses EXACT normalized subcategory matching - never loose substring matching.
/// This guarantees "Logon" is never confused with "Logoff" (BUG-05).
/// 
/// Handles:
///   - "System audit policy" header
///   - "Category/Subcategory  Setting" column header
///   - Category lines (2-space indent, no setting)
///   - Subcategory lines (4-space indent, ends with a valid setting)
///   - CRLF / LF newlines, BOM, whitespace
/// </summary>
public class AuditpolParser : IParser<string, AuditpolData>
{
    public string Name => "AuditpolParser";
    public string Version => "1.0.0";

    public IEnumerable<EvidenceSourceType> SupportedSources => new[]
    {
        EvidenceSourceType.Auditpol,
        EvidenceSourceType.Other
    };

    public bool CanParse(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Auditpol || source == EvidenceSourceType.Other;
    }

    public ParseResult<AuditpolData> Parse(string input)
    {
        return ParseInternal(input);
    }

    public Task<ParseResult<AuditpolData>> ParseAsync(string input)
    {
        return Task.FromResult(ParseInternal(input));
    }

    /// <summary>
    /// Extract the setting of one specific subcategory using EXACT match.
    /// Returns Missing if category or subcategory does not exist.
    /// </summary>
    public ParseResult<string> ExtractSetting(string rawOutput, string category, string subcategory)
    {
        var parseResult = ParseInternal(rawOutput);

        if (!parseResult.IsSuccess || parseResult.Value == null)
        {
            return parseResult.Map(_ => string.Empty);
        }

        var data = parseResult.Value;

        if (!data.GetEntriesInCategory(category).Any())
        {
            return ParseResult<string>.Missing(
                $"Category '{category}' not found in auditpol output",
                rawOutput);
        }

        if (!data.HasSubcategory(category, subcategory))
        {
            return ParseResult<string>.Missing(
                $"Subcategory '{subcategory}' not found in category '{category}'",
                rawOutput);
        }

        return ParseResult<string>.Success(data.GetSetting(category, subcategory)!, rawOutput);
    }

    // === PRIVATE ===

    private ParseResult<AuditpolData> ParseInternal(string rawOutput)
    {
        // Missing: empty/null input
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return ParseResult<AuditpolData>.Missing(
                "auditpol output is empty - command may have failed",
                rawOutput);
        }

        try
        {
            var data = new AuditpolData();
            var lines = NormalizeLines(rawOutput);
            string? currentCategory = null;

            foreach (var line in lines)
            {
                // Preserve leading whitespace for indent detection, trim trailing
                var trimmedEnd = line.TrimEnd();
                if (string.IsNullOrWhiteSpace(trimmedEnd))
                    continue;

                var trimmed = trimmedEnd.Trim();

                // Skip title header
                if (trimmed.Equals("System audit policy", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Skip column header
                if (trimmed.StartsWith("Category/Subcategory", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Try to interpret as subcategory line (ends with a valid setting)
                if (TryParseSubcategoryLine(trimmed, out var subcategory, out var setting))
                {
                    if (currentCategory == null)
                        continue; // subcategory outside category - tolerate

                    var entry = new AuditpolEntry
                    {
                        Category = currentCategory,
                        Subcategory = subcategory,
                        SettingRaw = setting
                    };

                    ApplySettingFlags(entry, setting);
                    data.AddEntry(entry);
                    continue;
                }

                // Otherwise it is a category line
                currentCategory = trimmed;
            }

            // Invalid: no entries parsed at all
            if (data.EntryCount == 0)
            {
                return ParseResult<AuditpolData>.Invalid(
                    "No category/subcategory entries found - not a valid auditpol output",
                    rawOutput);
            }

            return ParseResult<AuditpolData>.Success(data, rawOutput);
        }
        catch (Exception ex)
        {
            return ParseResult<AuditpolData>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Unexpected error parsing auditpol output: {ex.Message}",
                rawOutput);
        }
    }

    /// <summary>
    /// A subcategory line ends with one of the valid settings.
    /// The subcategory name is everything BEFORE the setting token.
    /// </summary>
    private static bool TryParseSubcategoryLine(string trimmed, out string subcategory, out string setting)
    {
        subcategory = string.Empty;
        setting = string.Empty;

        // Check settings from longest to shortest to avoid partial matches
        string[] validSettings =
        {
            "Success and Failure",
            "No Auditing",
            "Success",
            "Failure"
        };

        foreach (var s in validSettings)
        {
            if (trimmed.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            {
                var before = trimmed.Substring(0, trimmed.Length - s.Length).Trim();

                // There must be a non-empty subcategory name before the setting
                if (before.Length > 0)
                {
                    subcategory = before;
                    setting = s;
                    return true;
                }
            }
        }

        return false;
    }

    private static void ApplySettingFlags(AuditpolEntry entry, string setting)
    {
        switch (setting.ToLowerInvariant())
        {
            case "success and failure":
                entry.AuditSuccess = true;
                entry.AuditFailure = true;
                break;
            case "success":
                entry.AuditSuccess = true;
                entry.AuditFailure = false;
                break;
            case "failure":
                entry.AuditSuccess = false;
                entry.AuditFailure = true;
                break;
            case "no auditing":
            default:
                entry.AuditSuccess = false;
                entry.AuditFailure = false;
                break;
        }
    }

    private static IEnumerable<string> NormalizeLines(string rawOutput)
    {
        var cleaned = rawOutput
            .Replace("\0", string.Empty)
            .TrimStart('\uFEFF', '\uFFFE');

        return cleaned.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
    }
}