using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-03.7: Output Provenance Models
/// (audit KBF-01-010: raw stdout/stderr stored as undifferentiated text;
/// no stream identity, timestamps, or segment boundaries).
///
/// Every raw output line becomes exactly ONE typed segment — nothing is
/// dropped, nothing is guessed into certainty (Likely* kinds mark
/// inference honestly).
/// </summary>

public enum OutputStreamKind
{
    StdOut,   // H-03.7.1
    StdErr    // H-03.7.2
}

public enum OutputSegmentKind
{
    /// <summary>Empty line (preserved — nothing dropped).</summary>
    Empty,

    /// <summary>xUnit-style test result marker ("Passed!"/"Failed!"/"Skipped!").</summary>
    TestResultMarker,

    /// <summary>Looks like a stack frame ("   at NS.Type.Method(...)").</summary>
    LikelyStackFrame,

    /// <summary>xUnit framework diagnostic (exception block header/footer).</summary>
    FrameworkDiagnostic,

    /// <summary>dotnet/testhost infrastructure chatter.</summary>
    InfrastructureDiagnostic,

    /// <summary>Application/test code output (default, honest fallback).</summary>
    Application
}

/// <summary>One classified output line (or logical block) with provenance.</summary>
public sealed class OutputSegment
{
    public int LineIndex { get; init; }                 // 0-based across the stream
    public OutputStreamKind StreamKind { get; init; }
    public OutputSegmentKind SegmentKind { get; init; }
    public string Content { get; init; } = string.Empty;

    /// <summary>
    /// 3.7.3 — caller-supplied run timestamp (H-03.1 evidence). Line-level
    /// timestamps are impossible without a launcher adapter; null here is
    /// honest (X-004), NOT fabricated per-line.
    /// </summary>
    public DateTimeOffset? ObservedAtUtc { get; init; }

    /// <summary>H-03.7.5 marker: inferred classification (never certain).</summary>
    public bool IsInferred => SegmentKind is OutputSegmentKind.LikelyStackFrame
        or OutputSegmentKind.FrameworkDiagnostic
        or OutputSegmentKind.InfrastructureDiagnostic;
}

/// <summary>Aggregated provenance report.</summary>
public sealed class OutputProvenanceReport
{
    public List<OutputSegment> Segments { get; init; } = new();

    public int StdOutLineCount { get; init; }
    public int StdErrLineCount { get; init; }
    public int TotalSegmentCount { get; init; }

    public IReadOnlyList<OutputSegment> StdOutSegments { get; init; } = Array.Empty<OutputSegment>();
    public IReadOnlyList<OutputSegment> StdErrSegments { get; init; } = Array.Empty<OutputSegment>();

    public IReadOnlyList<OutputSegment> TestResultMarkers { get; init; } = Array.Empty<OutputSegment>();
    public IReadOnlyList<OutputSegment> LikelyStackFrames { get; init; } = Array.Empty<OutputSegment>();
    public IReadOnlyList<OutputSegment> FrameworkDiagnostics { get; init; } = Array.Empty<OutputSegment>();

    /// <summary>H-01.4 vocabulary: both streams observed (even if empty).</summary>
    public EvidenceState StdOutState { get; init; } = EvidenceState.Observed;
    public EvidenceState StdErrState { get; init; } = EvidenceState.Observed;
}