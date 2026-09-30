namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.3: Per-Test Coverage Mapping Models
/// (audit KBF-06-003 P0: TestCoverageInput was a manually shaped model;
/// no authoritative mapping from actual test IDs to covered lines existed
/// — SBFL could become synthetic rather than observed).
///
/// THE FIX: each per-test cobertura artifact (one per test execution,
/// coverlet per-test mode) maps to exactly ONE test identity — producing
/// an independent per-test spectrum. No manual shaping; the mapping is
/// derived from real artifacts + real TRX records (H-03.5).
/// </summary>
public enum PerTestMappingStatus
{
    Mapped,           // document attributed to a test
    Unmapped,         // document has no identifiable test (diagnostic)
    MissingCoverage   // test known but its document absent (diagnostic)
}

/// <summary>
/// One test's independent spectrum: ElementKey -> hit count.
/// ElementKey format: FILE|&lt;path&gt;|L&lt;line&gt; (H-01.7 normalized).
/// </summary>
public sealed class PerTestCoverage
{
    public PerTestMappingStatus Status { get; init; }

    /// <summary>Test identity from the TRX record (canonical H-01.6 form).</summary>
    public FailureIdentity? TestIdentity { get; init; }

    /// <summary>The test's full name (join key).</summary>
    public string TestFullName { get; init; } = string.Empty;

    /// <summary>The coverage artifact this spectrum came from (provenance, H-04.7).</summary>
    public string SourceArtifactPath { get; init; } = string.Empty;

    /// <summary>ElementKey -> hits (observed, not fabricated).</summary>
    public IReadOnlyDictionary<string, int> ElementHits { get; init; } =
        new Dictionary<string, int>();

    /// <summary>Diagnostic when unmapped/missing (mandatory for non-Mapped).</summary>
    public string? Reason { get; init; }

    public int CoveredElementCount => ElementHits.Count(kv => kv.Value > 0);
}

/// <summary>Aggregated per-test mapping report.</summary>
public sealed class PerTestCoverageReport
{
    /// <summary>One entry per test or per document — deterministic order.</summary>
    public IReadOnlyList<PerTestCoverage> Entries { get; init; } = Array.Empty<PerTestCoverage>();

    public int MappedCount { get; init; }
    public int UnmappedDocumentCount { get; init; }
    public int MissingCoverageCount { get; init; }

    public int TotalDistinctElements { get; init; }

    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}