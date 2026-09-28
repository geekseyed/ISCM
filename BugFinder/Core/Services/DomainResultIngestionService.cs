using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using ISCM.Domain.Enums;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-03.6: Domain Result Ingestion Service.
/// Stage 3.6.1  structured JSON array input (regex console parsing retired
///              at adoption; KBF-01-009's fragile single-format dependency
///              is structurally gone).
/// Stage 3.6.2  SubControlId — missing => record with EMPTY id + explicit
///              diagnostic (counted), never a silent skip.
/// Stage 3.6.3  Status — parsed case-insensitively into CheckStatus;
///              unparseable => CheckStatus.Unknown + RawStatus preserved
///              + diagnostic (H-01.4: unknown, not fabricated fail).
/// Stage 3.6.4  Reason — preserved as received.
/// Stage 3.6.5  Expected — preserved (KBF-01-008 fix).
/// Stage 3.6.6  Actual — preserved (KBF-01-008 fix).
/// Stage 3.6.7  SourceTestId — preserved (KBF-01-008 fix).
/// Stage 3.6.8  parser failures EXPLICIT: malformed elements counted
///              (SkippedMalformedCount) + diagnosed; bad JSON = Corrupt
///              with reason (anti-KBF-11-004).
///
/// Deterministic ordering: SubControlId then SourceTestId (ordinal).
/// </summary>
public class DomainResultIngestionService
{
    public DomainResultIngestionReport IngestFromFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Domain results path is required.", nameof(path));

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            return new DomainResultIngestionReport
            {
                Status = DomainResultIngestionStatus.FileMissing,
                SourceArtifactPath = fullPath,
                Reason = $"domain results artifact not found on disk: '{fullPath}'"
            };

        return IngestFromJson(File.ReadAllText(fullPath), fullPath);
    }

    public DomainResultIngestionReport IngestFromJson(
        string json, string sourceArtifactPath = "inline")
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("Domain results JSON is required.", nameof(json));

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            return new DomainResultIngestionReport
            {
                Status = DomainResultIngestionStatus.Corrupt,
                SourceArtifactPath = sourceArtifactPath,
                Reason = $"domain results JSON unreadable: {ex.Message} " +
                         "(corruption evidence preserved — H-06.4.4)"
            };
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return new DomainResultIngestionReport
                {
                    Status = DomainResultIngestionStatus.Corrupt,
                    SourceArtifactPath = sourceArtifactPath,
                    Reason = "domain results root must be a JSON array of records"
                };

            var elements = document.RootElement.EnumerateArray().ToList();
            if (elements.Count == 0)
                return new DomainResultIngestionReport
                {
                    Status = DomainResultIngestionStatus.NoRecords,
                    SourceArtifactPath = sourceArtifactPath,
                    Reason = "domain results array is empty"
                };

            var diagnostics = new List<string>();
            var records = new List<DomainEvaluationRecord>();
            var skipped = 0;
            var missingId = 0;
            var unparseableStatus = 0;

            foreach (var element in elements)
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    skipped++;
                    diagnostics.Add($"malformed record skipped: expected object, got {element.ValueKind}");
                    continue;
                }

                var subControlId = GetStringIgnoreCase(element, "subControlId")?.Trim() ?? string.Empty;
                if (subControlId.Length == 0)
                {
                    missingId++;
                    diagnostics.Add("record missing subControlId (recorded with empty id)");
                }

                var rawStatus = GetStringIgnoreCase(element, "status");
                CheckStatus status = CheckStatus.Unknown;
                if (rawStatus is null)
                {
                    unparseableStatus++;
                    diagnostics.Add($"record '{subControlId}': status absent -> Unknown");
                }
                else if (!Enum.TryParse<CheckStatus>(rawStatus.Trim(), ignoreCase: true, out status))
                {
                    unparseableStatus++;
                    diagnostics.Add($"record '{subControlId}': unparseable status '{rawStatus}' -> Unknown");
                    status = CheckStatus.Unknown;
                }

                records.Add(new DomainEvaluationRecord
                {
                    SubControlId = subControlId,
                    Status = status,
                    RawStatus = rawStatus,
                    Reason = GetStringIgnoreCase(element, "reason"),
                    Expected = GetStringIgnoreCase(element, "expected"),
                    Actual = GetStringIgnoreCase(element, "actual"),
                    SourceTestId = GetStringIgnoreCase(element, "sourceTestId")
                });
            }

            return new DomainResultIngestionReport
            {
                Status = DomainResultIngestionStatus.Ingested,
                SourceArtifactPath = sourceArtifactPath,
                Records = records
                    .OrderBy(r => r.SubControlId, StringComparer.Ordinal)
                    .ThenBy(r => r.SourceTestId ?? string.Empty, StringComparer.Ordinal)
                    .ToList(),
                TotalElementsSeen = elements.Count,
                SkippedMalformedCount = skipped,
                MissingSubControlIdCount = missingId,
                UnparseableStatusCount = unparseableStatus,
                Diagnostics = diagnostics
            };
        }
    }

    // ---------- internals ----------

    private static string? GetStringIgnoreCase(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                continue;

            return property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Null => null,
                _ => property.Value.ToString()   // numbers/bools preserved as text
            };
        }
        return null;
    }
}