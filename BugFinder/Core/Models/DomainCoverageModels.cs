using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.6: Domain Failure Coverage Models
/// (audit KBF-06-006 P0: CoverageEnrichmentService uses
/// failure.Identity.ClassName for lookup — domain failures are assigned
/// ClassName = "DomainEvaluation", which is NOT the source class of the
/// failing control; domain-failure -> code correlation is structurally
/// invalid for those records.
///  + KBF-06-007: fallback matching uses string Contains on class keys —
/// wrong classes can match when names overlap.
///  + KBF-06-008: "not covered" was reported as "Missing Test Scenario"
/// — it can also mean instrumentation gaps, mapping failure, generated
/// code, or unavailable coverage.)
///
/// THE FIX: a DomainEvaluationRecord (H-03.6) carries NO source symbol/
/// location — so identity is resolved from the ONE real pointer the
/// record has: SourceTestId (4.6.1). The matched test's mapped spectrum
/// (H-04.3) provides the covered elements (4.6.3). Unresolved/ambiguous
/// matches are explicit states with diagnostics (4.6.5). The service
/// CORRELATES and OBSERVES only — it never interprets "why" (no
/// "Missing Test Scenario" style claims — 4.6.6 / KBF-06-008).
/// </summary>
public enum DomainCorrelationState
{
    /// <summary>SourceTestId matched exactly, or via an unambiguous dotted-suffix.</summary>
    Correlated,

    /// <summary>Multiple distinct test names matched — never resolved by picking one (anti-KBF-13-008).</summary>
    Ambiguous,

    /// <summary>SourceTestId absent, or no test matched — explicit, diagnosed.</summary>
    Unresolved
}

public enum DomainCorrelationMatchKind
{
    /// <summary>SourceTestId == TestFullName (ordinal).</summary>
    Exact,

    /// <summary>SourceTestId == dotted tail of TestFullName ("&lt;name&gt;" == tail of "NS.Cls.&lt;name&gt;").</summary>
    DottedSuffix,

    /// <summary>No match (Unresolved) or multi-match (Ambiguous).</summary>
    None
}

/// <summary>One domain record's correlation outcome (4.6.1-4.6.6).</summary>
public sealed class DomainCoverageCorrelation
{
    public string SubControlId { get; init; } = string.Empty;

    /// <summary>Domain semantics PRESERVED verbatim (H-03.8.5) — never converted.</summary>
    public CheckStatus Status { get; init; }

    /// <summary>Raw status string as received (evidence even when unparseable).</summary>
    public string? RawStatus { get; init; }

    public string? Reason { get; init; }

    /// <summary>Verbatim from the domain record — the only identity pointer (4.6.1).</summary>
    public string? SourceTestId { get; init; }

    public DomainCorrelationState State { get; init; }
    public DomainCorrelationMatchKind MatchKind { get; init; }

    /// <summary>The matched test's full name — null when Ambiguous/Unresolved.</summary>
    public string? MatchedTestFullName { get; init; }

    /// <summary>Ambiguous candidates, ordinal-sorted — only when State == Ambiguous.</summary>
    public IReadOnlyList<string> AmbiguousCandidates { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Elements (FILE|path|L&lt;line&gt;) the matched test EXECUTED (hits&gt;0),
    /// ordinal-sorted. Instrumented-not-hit excluded — H-04.3
    /// CoveredElementCount continuity. Empty when unmatched OR when the
    /// matched test has no mapped spectrum (missing != zero).
    /// </summary>
    public IReadOnlyList<string> CoveredElementKeys { get; init; } = Array.Empty<string>();

    /// <summary>False = matched test exists but has NO mapped spectrum (missing coverage ≠ zero coverage, H-01.4).</summary>
    public bool MatchedTestHasCoverageSpectrum { get; init; }
}

/// <summary>
/// The domain-failure coverage report. Source status is carried so zero
/// counts on a non-Ingested source read "not measured", never "no
/// failures" (H-01.4 / anti-KBF-11-007).
/// </summary>
public sealed class DomainCoverageReport
{
    public DomainResultIngestionStatus SourceStatus { get; init; }
    public string SourceArtifactPath { get; init; } = string.Empty;

    /// <summary>One correlation per domain record, deterministic ordinal order.</summary>
    public IReadOnlyList<DomainCoverageCorrelation> Correlations { get; init; } =
        Array.Empty<DomainCoverageCorrelation>();

    public int CorrelatedCount { get; init; }
    public int AmbiguousCount { get; init; }
    public int UnresolvedCount { get; init; }

    /// <summary>Exclusions, ambiguities, absent identities — never silently dropped.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}