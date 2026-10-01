namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.5: Pass/Fail Spectrum Models
/// (audit KBF-06-004 P1: CoverageSpectrumBuilderService treats every
/// non-passed test as failed because totalFailed = Count(!IsPassed) —
/// skipped/unknown outcomes contaminate the spectrum).
///
/// THE FIX: outcomes are explicit buckets mapped from the REAL TRX raw
/// outcome (H-03.5) — never a bool. Only Passed/Failed/Error enter the
/// element counters; Skipped/Unavailable/Unknown are excluded WITH
/// diagnostics (KBF-06-004 fix).
/// </summary>
public enum SpectrumTestOutcome
{
    /// <summary>Stage 4.5.1 — passed tests.</summary>
    Passed,

    /// <summary>Stage 4.5.2 — failed tests (assertion failures).</summary>
    Failed,

    /// <summary>Stage 4.5.3 — error results (non-assertion failure) — a SEPARATE bucket, never merged into Failed.</summary>
    Error,

    /// <summary>NotExecuted/Skipped — NEVER counted as failed (KBF-06-004).</summary>
    Skipped,

    /// <summary>Stage 4.5.4 — NotRunnable/Disconnected: infrastructure-level unavailability, not a test defect.</summary>
    Unavailable,

    /// <summary>Unrecognized or absent raw outcome — preserved verbatim, never guessed.</summary>
    Unknown
}

/// <summary>One test's explicit outcome with full provenance (4.5.5).</summary>
public sealed class TestOutcomeClassification
{
    public string TestFullName { get; init; } = string.Empty;

    /// <summary>Stage 4.5.5 — raw TRX outcome VERBATIM (may be empty when the attribute is absent).</summary>
    public string RawOutcome { get; init; } = string.Empty;

    public SpectrumTestOutcome Outcome { get; init; }

    /// <summary>Stage 4.5.5 — provenance: the TRX artifact this outcome came from.</summary>
    public string TrxArtifactPath { get; init; } = string.Empty;

    /// <summary>Stage 4.5.5 — provenance: real assembly identity (H-03.5.2, never hard-coded).</summary>
    public string AssemblyPath { get; init; } = string.Empty;

    /// <summary>H-03.5.7 continuity — unknown definitions remain preserved.</summary>
    public bool IsUnknownDefinition { get; init; }
}

/// <summary>
/// One element's outcome counters (the SBFL aep/aef raw material —
/// H-04.8 verifies, BF-12 consumes). Error is counted separately from
/// Failed so downstream fusion decides whether to merge.
/// </summary>
public sealed class ElementOutcomeSpectrum
{
    /// <summary>H-04.3/4.4 join key: FILE|&lt;path&gt;|L&lt;line&gt;.</summary>
    public string ElementKey { get; init; } = string.Empty;

    /// <summary>Stage 4.5.1 — mapped PASSED tests that executed this element (aep).</summary>
    public int PassedHitCount { get; init; }

    /// <summary>Stage 4.5.2 — mapped FAILED tests that executed this element (aef).</summary>
    public int FailedHitCount { get; init; }

    /// <summary>Stage 4.5.3 — mapped ERROR tests that executed this element — separate, never merged into Failed.</summary>
    public int ErrorHitCount { get; init; }
}

/// <summary>
/// The Pass/Fail spectrum report. Counts are computed from explicit
/// classifications — never derived by negation (anti-KBF-06-004).
/// </summary>
public sealed class PassFailSpectrumReport
{
    /// <summary>Verbatim TRX source status — zero counts when not Ingested mean "no outcomes measured", NOT "no failures".</summary>
    public TrxIngestionStatus SourceStatus { get; init; }

    public string SourceArtifactPath { get; init; } = string.Empty;

    /// <summary>One classification per TRX record, ordinal-ordered.</summary>
    public IReadOnlyList<TestOutcomeClassification> TestOutcomes { get; init; } =
        Array.Empty<TestOutcomeClassification>();

    /// <summary>Element counters from mapped spectra of classifiable tests, ordinal-ordered (deterministic).</summary>
    public IReadOnlyList<ElementOutcomeSpectrum> Elements { get; init; } =
        Array.Empty<ElementOutcomeSpectrum>();

    public int PassedTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Passed);
    public int FailedTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Failed);
    public int ErrorTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Error);
    public int SkippedTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Skipped);
    public int UnavailableTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Unavailable);
    public int UnknownTestCount => TestOutcomes.Count(t => t.Outcome == SpectrumTestOutcome.Unknown);

    /// <summary>Exclusions, ambiguities, non-ingested sources — never silently dropped.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}