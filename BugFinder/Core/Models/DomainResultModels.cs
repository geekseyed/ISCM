using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-03.6: Domain Result Ingestion Models
/// (audit KBF-01-008: only SubControlId/Status/Reason were ingested —
/// Expected/Actual/SourceTestId were lost; KBF-01-009: single-regex
/// console parsing silently ignored non-matching lines).
///
/// FORMAT (documented v1): a JSON ARRAY of objects with the fields
/// below (property names case-insensitive):
/// [
///   { "subControlId": "EVL-001.4", "status": "Fail",
///     "reason": "expected 512 MB, actual 128 MB",
///     "expected": "512", "actual": "128",
///     "sourceTestId": "EventLogSizeCheck_Test" }
/// ]
///
/// PARSER FAILURES ARE EXPLICIT (3.6.8): bad JSON = Corrupt; malformed
/// records and unparseable statuses are counted + diagnosed — never
/// silently skipped.
/// </summary>
public enum DomainResultIngestionStatus
{
    Ingested,
    FileMissing,
    Corrupt,        // bad JSON / not an array / wrong shape (reason mandatory)
    NoRecords       // parsed, zero records (explicit — never fabricated success)
}

/// <summary>One domain evaluation record with ALL SIX canonical fields.</summary>
public sealed class DomainEvaluationRecord
{
    public string SubControlId { get; init; } = string.Empty;
    public CheckStatus Status { get; init; } = CheckStatus.Unknown;

    /// <summary>Raw status string as received (evidence even when unparseable).</summary>
    public string? RawStatus { get; init; }

    public string? Reason { get; init; }
    public string? Expected { get; init; }
    public string? Actual { get; init; }
    public string? SourceTestId { get; init; }

    /// <summary>
    /// H-02.1 adoption bridge: projects into the BF-01 normalized shape
    /// consumed by FailureSignatureMaterialFactory.FromDomainEvaluation.
    /// </summary>
    public NormalizedEvaluationResult ToNormalizedEvaluationResult() => new()
    {
        SubControlId = SubControlId,
        Status = Status,
        Reason = Reason,
        Expected = Expected,
        Actual = Actual,
        SourceTestId = SourceTestId
    };
}

/// <summary>Ingestion report — explicit states + per-record diagnostics.</summary>
public sealed class DomainResultIngestionReport
{
    public DomainResultIngestionStatus Status { get; init; }
    public string SourceArtifactPath { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;   // mandatory for non-Ingested

    public IReadOnlyList<DomainEvaluationRecord> Records { get; init; } =
        Array.Empty<DomainEvaluationRecord>();

    public int TotalElementsSeen { get; init; }
    public int SkippedMalformedCount { get; init; }
    public int MissingSubControlIdCount { get; init; }
    public int UnparseableStatusCount { get; init; }

    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}