using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-03.7: Output Provenance Service.
/// Stage 3.7.1/3.7.2  stream identity: every segment carries StdOut/StdErr.
/// Stage 3.7.3        timestamps: caller-supplied run timestamp (from
///                    H-03.1 evidence); per-line timestamps are null by
///                    design (honest — needs a launcher adapter, H-13).
/// Stage 3.7.4        segmentation: one segment per raw line; empty lines
///                    preserved as Empty segments (nothing dropped).
/// Stage 3.7.5        framework/application/diagnostic separation with
///                    honest inference (Likely* kinds never claimed as fact).
///
/// NOTHING IS DROPPED: output line count == segment count per stream.
/// Classification rules are pure functions (deterministic, testable).
/// Case-sensitive matching for result markers (they are protocol-ish).
/// </summary>
public class OutputProvenanceService
{
    private const string PassedMarker = "Passed!";
    private const string FailedMarker = "Failed!";
    private const string SkippedMarker = "Skipped!";

    public OutputProvenanceReport Build(
        string? stdout,
        string? stderr,
        DateTimeOffset? observedAtUtc = null)
    {
        var segments = new List<OutputSegment>();
        var stdOutLines = 0;
        var stdErrLines = 0;

        AppendStream(segments, OutputStreamKind.StdOut, stdout, ref stdOutLines, observedAtUtc);
        AppendStream(segments, OutputStreamKind.StdErr, stderr, ref stdErrLines, observedAtUtc);

        var stdOutSegments = segments.Where(s => s.StreamKind == OutputStreamKind.StdOut).ToList();
        var stdErrSegments = segments.Where(s => s.StreamKind == OutputStreamKind.StdErr).ToList();

        return new OutputProvenanceReport
        {
            Segments = segments,
            StdOutSegments = stdOutSegments,
            StdErrSegments = stdErrSegments,
            StdOutLineCount = stdOutLines,
            StdErrLineCount = stdErrLines,
            TotalSegmentCount = segments.Count,
            TestResultMarkers = segments.Where(s => s.SegmentKind == OutputSegmentKind.TestResultMarker).ToList(),
            LikelyStackFrames = segments.Where(s => s.SegmentKind == OutputSegmentKind.LikelyStackFrame).ToList(),
            FrameworkDiagnostics = segments.Where(s => s.SegmentKind == OutputSegmentKind.FrameworkDiagnostic).ToList(),
            StdOutState = EvidenceState.Observed,   // stream WAS captured (even empty)
            StdErrState = EvidenceState.Observed
        };
    }

    private static void AppendStream(
    List<OutputSegment> segments,
    OutputStreamKind streamKind,
    string? raw,
    ref int lineCounter,
    DateTimeOffset? observedAtUtc)
    {
        // null stream = stream not captured (no segments, state still Observed)
        if (raw is null)
        {
            return;
        }

        // empty string = a REAL observed empty stream -> zero segments (X-004:
        // empty is real, but an empty stream produces no lines to segment)
        if (raw.Length == 0)
        {
            return;
        }

        var lines = raw.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');
            var content = line.Trim();

            segments.Add(new OutputSegment
            {
                LineIndex = lineCounter++,
                StreamKind = streamKind,
                SegmentKind = Classify(content),
                Content = content,
                ObservedAtUtc = observedAtUtc          // H-03.7.3 — propagate
            });
        }
    }

    /// <summary>Stage 3.7.5 — pure classification function (deterministic).</summary>
    private static OutputSegmentKind Classify(string content)
    {
        if (content.Length == 0) return OutputSegmentKind.Empty;

        if (content.StartsWith(PassedMarker, StringComparison.Ordinal)
            || content.StartsWith(FailedMarker, StringComparison.Ordinal)
            || content.StartsWith(SkippedMarker, StringComparison.Ordinal))
            return OutputSegmentKind.TestResultMarker;

        // stack-frame shape: indented "at " + method( + args
        if (content.StartsWith("at ", StringComparison.Ordinal)
            || content.StartsWith("   at ", StringComparison.Ordinal))
            return OutputSegmentKind.LikelyStackFrame;

        // xUnit exception block headers
        if (content.Contains("Xunit.Sdk.", StringComparison.Ordinal)
            || content.StartsWith("Exception message:", StringComparison.Ordinal)
            || content.StartsWith("Stack trace:", StringComparison.Ordinal))
            return OutputSegmentKind.FrameworkDiagnostic;

        // testhost / infrastructure chatter
        if (content.StartsWith("Test run for", StringComparison.Ordinal)
            || content.Contains("testhost", StringComparison.OrdinalIgnoreCase)
            || content.StartsWith("NUnit Adapter", StringComparison.Ordinal))
            return OutputSegmentKind.InfrastructureDiagnostic;

        return OutputSegmentKind.Application;
    }
}