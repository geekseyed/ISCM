using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class OutputProvenanceTests
{
    private readonly OutputProvenanceService _service = new();

    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    // H-03.7.1/3.7.2 — stream identity preserved
    [Fact]
    public void Build_StreamIdentity_StdOutAndStdErrSeparated()
    {
        var report = _service.Build("out-line", "err-line", T0);

        report.StdOutSegments.Should().ContainSingle(s =>
            s.Content == "out-line" && s.StreamKind == OutputStreamKind.StdOut);
        report.StdErrSegments.Should().ContainSingle(s =>
            s.Content == "err-line" && s.StreamKind == OutputStreamKind.StdErr);
        report.StdOutLineCount.Should().Be(1);
        report.StdErrLineCount.Should().Be(1);
        report.TotalSegmentCount.Should().Be(2);
    }

    // H-03.7.4 — nothing dropped: every raw line becomes one segment
    [Fact]
    public void Build_NothingDropped_LineCountEqualsSegmentCount()
    {
        var stdout = "line1\nline2\n\nline4";   // includes one empty line
        var stderr = "err1\nerr2";

        var report = _service.Build(stdout, stderr, T0);

        report.TotalSegmentCount.Should().Be(6);
        report.StdOutLineCount.Should().Be(4);
        report.StdErrLineCount.Should().Be(2);

        // empty line preserved as Empty segment (X-004: empty is real)
        report.Segments.Should().Contain(s =>
            s.SegmentKind == OutputSegmentKind.Empty && s.Content == string.Empty);
    }

    // H-03.7.4 — segmentation classification
    [Fact]
    public void Build_TestResultMarkers_Classified()
    {
        var stdout = "Passed! - Failed: 0\nFailed! - Failed: 2\nSkipped! - Skipped: 1";

        var report = _service.Build(stdout, null, T0);

        report.TestResultMarkers.Should().HaveCount(3);
        report.TestResultMarkers.Should().OnlyContain(s =>
            s.StreamKind == OutputStreamKind.StdOut);
    }

    // H-03.7.5 — stack frames inferred (Likely, never certain)
    [Fact]
    public void Build_StackFrames_MarkedAsLikely()
    {
        var stderr = "   at NS.MyClass.Method() in Calc.cs:line 42";

        var report = _service.Build(null, stderr, T0);

        report.LikelyStackFrames.Should().ContainSingle(s =>
            s.SegmentKind == OutputSegmentKind.LikelyStackFrame
            && s.StreamKind == OutputStreamKind.StdErr
            && s.IsInferred);
    }

    // H-03.7.5 — xUnit framework diagnostics
    [Fact]
    public void Build_FrameworkDiagnostics_Classified()
    {
        var stderr = "Exception message: boom\nXunit.Sdk.EqualException: expected";

        var report = _service.Build(null, stderr, T0);

        report.FrameworkDiagnostics.Should().HaveCount(2);
        report.FrameworkDiagnostics.Should().OnlyContain(s => s.IsInferred);
    }

    // H-03.7.5 — infrastructure chatter
    [Fact]
    public void Build_Infrastructure_Chatter_Classified()
    {
        var stdout = "Test run for ISCM.Tests.dll (.NETCoreApp,Version=v8.0)";

        var report = _service.Build(stdout, null, T0);

        report.Segments.Should().Contain(s =>
            s.SegmentKind == OutputSegmentKind.InfrastructureDiagnostic);
    }

    // Default fallback = Application (honest, not inferred)
    [Fact]
    public void Build_ApplicationOutput_DefaultKind_NotInferred()
    {
        var report = _service.Build("app wrote something", null, T0);

        var segment = report.StdOutSegments.Single();
        segment.SegmentKind.Should().Be(OutputSegmentKind.Application);
        segment.IsInferred.Should().BeFalse();
    }

    // H-03.7.3 — caller-supplied timestamp propagated; per-line stays null
    [Fact]
    public void Build_Timestamps_CallerSuppliedNotFabricated()
    {
        var report = _service.Build("line", "line2", T0);

        report.Segments.Should().OnlyContain(s => s.ObservedAtUtc == T0);
        report.Segments.Should().OnlyContain(s => s.ObservedAtUtc.HasValue);
    }

    // Empty streams — Observed (X-004: empty is real, not unavailable)
    [Fact]
    public void Build_EmptyStreams_ObservedStates()
    {
        var report = _service.Build(string.Empty, null, T0);

        report.StdOutState.Should().Be(EvidenceState.Observed);
        report.StdErrState.Should().Be(EvidenceState.Observed);
        report.TotalSegmentCount.Should().Be(0);   // empty string -> zero lines
    }

    // Null streams — segments empty but states still Observed (streams captured)
    [Fact]
    public void Build_NullStreams_ZeroSegments_ObservedStates()
    {
        var report = _service.Build(null, null, T0);

        report.TotalSegmentCount.Should().Be(0);
        report.StdOutState.Should().Be(EvidenceState.Observed);
        report.StdErrState.Should().Be(EvidenceState.Observed);
    }

    // CRLF handling — \r\n lines don't leave \r residue
    [Fact]
    public void Build_CrLf_Lines_Trimmed()
    {
        var stdout = "line1\r\nline2\r\n";

        var report = _service.Build(stdout, null, T0);

        report.StdOutSegments.Select(s => s.Content)
            .Should().ContainInOrder("line1", "line2", string.Empty);
    }

    // Integration with H-03.1 evidence — timestamp from real evidence
    [Fact]
    public void Build_WithEvidenceTimestamp_Propagated()
    {
        var stdout = "Failed! - Failed: 1";
        var evidence = new ProcessExecutionEvidence { StartUtc = T0, EndUtc = T0.AddSeconds(5) };

        var report = _service.Build(stdout, null, evidence.EndUtc);

        report.TestResultMarkers.Single().ObservedAtUtc.Should().Be(evidence.EndUtc);
    }

    // Ordering — segments in stream order: stdout block then stderr block
    [Fact]
    public void Build_Ordering_StdOutThenStdErr()
    {
        var report = _service.Build("o1\no2", "e1", T0);

        report.Segments.Select(s => s.StreamKind)
            .Should().ContainInOrder(
                OutputStreamKind.StdOut, OutputStreamKind.StdOut, OutputStreamKind.StdErr);
    }

    // Classification is deterministic (same input twice = same output)
    [Fact]
    public void Build_Deterministic()
    {
        var first = _service.Build("Failed!\n   at X.Y()", "Xunit.Sdk.EqualException", T0);
        var second = _service.Build("Failed!\n   at X.Y()", "Xunit.Sdk.EqualException", T0);

        first.Segments.Select(s => (s.SegmentKind, s.Content))
            .Should().Equal(second.Segments.Select(s => (s.SegmentKind, s.Content)));
    }
}