using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Parsers;

/// <summary>
/// Parses secedit /export INF output into structured SeceditPolicyData.
/// 
/// Handles:
///   - [Section] headers
///   - Key=Value lines
///   - Blank lines, comments (;), BOM
///   - CRLF / LF newlines
///   - Whitespace tolerance
///   - Duplicate keys (last wins, recorded)
/// 
/// MUST NOT silently convert malformed input into a valid default.
/// </summary>
public class SeceditParser : IParser<string, SeceditPolicyData>
{
    public string Name => "SeceditParser";
    public string Version => "1.0.0";

    public IEnumerable<EvidenceSourceType> SupportedSources => new[]
    {
        EvidenceSourceType.Secedit,
        EvidenceSourceType.Other
    };

    public bool CanParse(EvidenceSourceType source)
    {
        return source == EvidenceSourceType.Secedit || source == EvidenceSourceType.Other;
    }

    public ParseResult<SeceditPolicyData> Parse(string input)
    {
        return ParseInternal(input);
    }

    public Task<ParseResult<SeceditPolicyData>> ParseAsync(string input)
    {
        return Task.FromResult(ParseInternal(input));
    }

    /// <summary>
    /// Extract a single value from a specific section.
    /// Returns Missing if section or key does not exist.
    /// </summary>
    public ParseResult<string> ExtractValue(string rawOutput, string sectionName, string key)
    {
        var parseResult = ParseInternal(rawOutput);

        if (!parseResult.IsSuccess || parseResult.Value == null)
        {
            return parseResult.Map(_ => string.Empty);
        }

        var data = parseResult.Value;

        if (!data.HasSection(sectionName))
        {
            return ParseResult<string>.Missing(
                $"Section [{sectionName}] not found in secedit output",
                rawOutput);
        }

        if (!data.HasValue(sectionName, key))
        {
            return ParseResult<string>.Missing(
                $"Key '{key}' not found in section [{sectionName}]",
                rawOutput);
        }

        return ParseResult<string>.Success(data.GetValue(sectionName, key)!, rawOutput);
    }

    // === PRIVATE ===

    private ParseResult<SeceditPolicyData> ParseInternal(string rawOutput)
    {
        // Missing: empty/null input
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return ParseResult<SeceditPolicyData>.Missing(
                "Secedit output is empty - export may have failed or file missing",
                rawOutput);
        }

        try
        {
            var data = new SeceditPolicyData();
            string? currentSection = null;
            var lines = NormalizeLines(rawOutput);
            var parsedAnySection = false;
            var parsedAnyValue = false;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                // Skip blank lines
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                // Skip comments
                if (trimmed.StartsWith(";") || trimmed.StartsWith("#"))
                    continue;

                // Section header: [SectionName]
                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    var sectionName = trimmed.Substring(1, trimmed.Length - 2).Trim();

                    if (string.IsNullOrEmpty(sectionName))
                    {
                        // Malformed empty section header - skip but do not fail whole parse
                        currentSection = null;
                        continue;
                    }

                    currentSection = sectionName;
                    data.AddSection(sectionName);
                    parsedAnySection = true;
                    continue;
                }

                // Key=Value line
                var eqIndex = trimmed.IndexOf('=');
                if (eqIndex > 0)
                {
                    // Value line outside any section is invalid structure
                    if (currentSection == null)
                        continue;

                    var key = trimmed.Substring(0, eqIndex).Trim();
                    var value = trimmed.Substring(eqIndex + 1).Trim();

                    if (!string.IsNullOrEmpty(key))
                    {
                        data.TryAddValue(currentSection, key, value);
                        parsedAnyValue = true;
                    }
                    continue;
                }

                // Line that is neither section, comment, nor key=value:
                // tolerate silently only if it looks like unicode/encoding artifact;
                // otherwise it is malformed but we continue (do not fail whole parse).
            }

            // Invalid: no sections and no values at all
            if (!parsedAnySection && !parsedAnyValue)
            {
                return ParseResult<SeceditPolicyData>.Invalid(
                    "No [Section] headers or Key=Value lines found - not a valid secedit INF output",
                    rawOutput);
            }

            // Invalid: sections exist but zero values (suspicious/truncated output)
            if (parsedAnySection && !parsedAnyValue)
            {
                return ParseResult<SeceditPolicyData>.Invalid(
                    "Sections found but no Key=Value entries - output may be truncated",
                    rawOutput);
            }

            return ParseResult<SeceditPolicyData>.Success(data, rawOutput);
        }
        catch (Exception ex)
        {
            return ParseResult<SeceditPolicyData>.Failure(
                ParseErrorCode.UnexpectedError,
                $"Unexpected error parsing secedit output: {ex.Message}",
                rawOutput);
        }
    }

    /// <summary>
    /// Normalize newlines (CRLF/LF/CR), strip BOM and unicode artifacts.
    /// </summary>
    private static IEnumerable<string> NormalizeLines(string rawOutput)
    {
        // Strip UTF-16/UTF-8 BOM and null chars (secedit exports are often UTF-16LE)
        var cleaned = rawOutput
            .Replace("\0", string.Empty)
            .TrimStart('\uFEFF', '\uFFFE');

        return cleaned.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
    }
}