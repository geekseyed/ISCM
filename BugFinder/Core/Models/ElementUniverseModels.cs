namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.4: Element Universe Models
/// (audit KBF-06-005: the spectrum universe was built only from lines
/// present in at least one CoveredLines list — unseen source lines were
/// absent rather than explicitly unexecuted).
///
/// THE FIX: the universe is derived from COVERAGE METADATA (every line
/// the collector instrumented — H-04.2 documents, hits=0 included), NOT
/// from observed hits alone. Uncovered elements are explicit members of
/// the universe with state=Uncovered; they are never silently absent.
///
/// Stage 4.4.1  analyzable element: one instrumented source line, keyed
///              FILE|&lt;path&gt;|L&lt;line&gt; (H-01.7 normalized — the same
///              ElementKey format the H-04.3 spectra use; one join key).
/// Stage 4.4.2  non-executable exclusion: only instrumented lines enter
///              the universe (cobertura emits instrumented lines only —
///              non-executable lines never appear, by collector truth).
/// Stage 4.4.3  uncovered preservation: instrumented + zero hits across
///              all mapped tests = Uncovered — an explicit state, not
///              absence (Zero != Missing, H-01.4.8).
/// Stage 4.4.4  unknown preservation: an element observed in a mapped
///              spectrum but absent from coverage metadata is Unknown —
///              kept, never dropped (Unknown != Unavailable, H-01.4.6).
/// Stage 4.4.5  determinism: ordinal ordering by ElementKey; no clock,
///              no Guid (audit X-003 continuity).
/// </summary>
public enum ElementUniverseState
{
    /// <summary>Instrumented per coverage metadata and hit (&gt;0) by at least one mapped test.</summary>
    Covered,

    /// <summary>Instrumented per coverage metadata but not hit by any mapped test (hits=0) — explicitly unexecuted.</summary>
    Uncovered,

    /// <summary>Observed in a mapped spectrum but NOT present in coverage metadata — executability unproven (4.4.4).</summary>
    Unknown
}

/// <summary>
/// One analyzable element of the coverage universe (Stage 4.4.1): a
/// single instrumented source line, or an element observed in a spectrum
/// without instrumented backing (Unknown).
/// </summary>
public sealed class UniverseElement
{
    /// <summary>H-01.7 normalized key: FILE|&lt;path&gt;|L&lt;line&gt; — identical to the H-04.3 spectrum key.</summary>
    public string ElementKey { get; init; } = string.Empty;

    /// <summary>The normalized source-file path part of the key.</summary>
    public string SourceFilePath { get; init; } = string.Empty;

    /// <summary>1-based source line number.</summary>
    public int LineNumber { get; init; }

    public ElementUniverseState State { get; init; }

    /// <summary>True when coverage metadata (H-04.2) contains this line — the collector instrumented it.</summary>
    public bool IsInstrumented { get; init; }

    /// <summary>Highest hit count observed for this element across MAPPED test spectra (observed, never fabricated).</summary>
    public int MaxObservedHits { get; init; }
}

/// <summary>
/// The deterministic element universe (Stage 4.4 output): every analyzable
/// element exactly once, ordinal-ordered by ElementKey — stable across
/// repeated runs on identical inputs.
/// </summary>
public sealed class ElementUniverseReport
{
    /// <summary>All universe elements, ordinal-ordered by ElementKey (Stage 4.4.5).</summary>
    public IReadOnlyList<UniverseElement> Elements { get; init; } = Array.Empty<UniverseElement>();

    public int TotalCount => Elements.Count;
    public int CoveredCount => Elements.Count(e => e.State == ElementUniverseState.Covered);
    public int UncoveredCount => Elements.Count(e => e.State == ElementUniverseState.Uncovered);
    public int UnknownCount => Elements.Count(e => e.State == ElementUniverseState.Unknown);

    /// <summary>Distinct parsed coverage artifacts (H-04.2) the instrumented universe was derived from, ordinal-ordered (provenance seed, H-04.7).</summary>
    public IReadOnlyList<string> SourceArtifactPaths { get; init; } = Array.Empty<string>();

    /// <summary>Non-fatal anomalies (non-Parsed documents skipped, malformed spectrum keys) — never silently dropped.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}