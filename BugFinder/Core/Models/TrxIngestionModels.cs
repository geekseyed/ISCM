namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-03.5: TRX Ingestion Integrity Models
/// (audit KBF-01-005/006/007 — silent skip, hard-coded assembly,
/// fabricated timestamps).
///
/// The service parses a REAL TRX XML file into structured records with
/// explicit corrupt/unavailable states - never fabricated empty states
/// (anti-KBF-11-004).
/// </summary>

public enum TrxIngestionStatus
{
    Ingested,        // TRX parsed, records extracted
    FileMissing,     // path does not exist (explicit)
    Corrupt,         // reached but unreadable XML (explicit, reason mandatory)
    NoResults        // parsed but zero UnitTestResult elements (explicit, not "empty")
}

/// <summary>
/// One test result record from the TRX.
/// NOTE: assembly identity is the REAL storage/codeBase from the
/// TestDefinitions block — NEVER a hard-coded name (KBF-01-006).
/// </summary>
public sealed class TrxTestRecord
{
    /// <summary>executionId attribute of the UnitTestResult (correlation to testElement).</summary>
    public string ExecutionId { get; init; } = string.Empty;

    /// <summary>testName attribute of the UnitTestResult.</summary>
    public string TestName { get; init; } = string.Empty;

    /// <summary>
    /// Resolved test identity: prefer TestDefinitions/@name when the
    /// executionId matches; fall back to result/@testName for unknown
    /// definitions (which are PRESERVED, never skipped — KBF-01-005).
    /// </summary>
    public string TestFullName { get; init; } = string.Empty;

    /// <summary>
    /// Real assembly identity: TestDefinitions/UnitTest/@storage (or
    /// @codeBase), slash-normalized. Empty = unknown (never fabricated).
    /// </summary>
    public string AssemblyPath { get; init; } = string.Empty;

    public string Outcome { get; init; } = string.Empty;   // Passed/Failed/NotExecuted/...

    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? CompletedUtc { get; init; }
    public TimeSpan? Duration { get; init; }

    /// <summary>True when the executionId had no matching TestDefinition (3.5.7).</summary>
    public bool IsUnknownDefinition { get; init; }
}

/// <summary>Aggregated ingestion report.</summary>
public sealed class TrxIngestionReport
{
    public TrxIngestionStatus Status { get; init; }
    public string SourceArtifactPath { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;    // mandatory for non-Ingested

    public IReadOnlyList<TrxTestRecord> Records { get; init; } = Array.Empty<TrxTestRecord>();

    /// <summary>3.5.7: unknown-definition records are PRESERVED (counted).</summary>
    public int UnknownDefinitionCount { get; init; }

    /// <summary>Diagnostics: skipped elements, missing attributes, etc.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    /// <summary>Test run metadata (TestRun/times) — null when absent.</summary>
    public DateTimeOffset? RunStartedUtc { get; init; }
    public DateTimeOffset? RunFinishedUtc { get; init; }
}