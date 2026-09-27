using System;
using System.Collections.Generic;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class RegressionIsolationTests
{
    private const string P = "P0";       // trusted passing boundary
    private const string F = "HEAD";     // trusted failing boundary

    // Hand-trace A: candidates [c1..c4], truth: c3 first failing ({c3,c4} fail)
    // seq: P0,c1,c2,c3,c4,HEAD (idx 0..5) | lo=0,hi=5
    //   mid=2 -> c2 PASS -> lo=2 | mid=3 -> c3 FAIL -> hi=3 | gap=1 stop
    [Fact]
    public void Isolate_MidRangeFailure_HandTracedBisection()
    {
        var gateway = new ScriptedRevisionTestGateway(new[] { "c3", "c4" });

        var report = new RegressionIsolationService().Isolate(
            "MidRange", new[] { "c1", "c2", "c3", "c4" }, P, F, gateway);

        report.Status.Should().Be(RegressionIsolationStatus.Isolated);
        report.FirstFailingCommitId.Should().Be("c3");
        report.LastPassingCommitId.Should().Be("c2");
        report.TestedCommitIds.Should().ContainInOrder("c2", "c3");
        report.Tests[0].WasFailing.Should().BeFalse();
        report.Tests[1].WasFailing.Should().BeTrue();
        report.TestCount.Should().Be(2);
        report.WorstCaseBound.Should().Be(3);           // ceil(log2(5))
        report.WithinBound.Should().BeTrue();
        report.MonotonicityAssumed.Should().BeTrue();
        gateway.CallCount.Should().Be(2);               // gateway contract agrees
        gateway.Source.Should().Be(RevisionTestSource.Scripted);
    }

    // Hand-trace B: truth: c1 first failing ({c1..c4} fail)
    //   mid=2 -> c2 FAIL -> hi=2 | mid=1 -> c1 FAIL -> hi=1 | stop
    [Fact]
    public void Isolate_RangeStartFailure_FastConvergence()
    {
        var gateway = new ScriptedRevisionTestGateway(new[] { "c1", "c2", "c3", "c4" });

        var report = new RegressionIsolationService().Isolate(
            "RangeStart", new[] { "c1", "c2", "c3", "c4" }, P, F, gateway);

        report.FirstFailingCommitId.Should().Be("c1");
        report.LastPassingCommitId.Should().Be(P);
        report.TestedCommitIds.Should().ContainInOrder("c2", "c1");
        report.TestCount.Should().Be(2);
        report.WithinBound.Should().BeTrue();
    }

    // Hand-trace C: all candidates pass -> boundary is the known-failing HEAD
    //   mid=2 pass | mid=3 pass | mid=4 pass | stop -> exactly the bound
    [Fact]
    public void Isolate_AllCandidatesPass_BoundaryIsKnownFailing_AtExactBound()
    {
        var gateway = new ScriptedRevisionTestGateway(Array.Empty<string>());

        var report = new RegressionIsolationService().Isolate(
            "AllPass", new[] { "c1", "c2", "c3", "c4" }, P, F, gateway);

        report.Status.Should().Be(RegressionIsolationStatus.Isolated);
        report.FirstFailingCommitId.Should().Be(F);
        report.LastPassingCommitId.Should().Be("c4");
        report.TestedCommitIds.Should().ContainInOrder("c2", "c3", "c4");
        report.TestCount.Should().Be(3);
        report.WorstCaseBound.Should().Be(3);           // worst case reached exactly
        report.WithinBound.Should().BeTrue();
    }

    // Stage 4 trivial case: adjacent boundaries -> zero tests, honest status
    [Fact]
    public void Isolate_NoCandidates_ZeroTestsBoundaryIsKnownFailing()
    {
        var gateway = new ScriptedRevisionTestGateway(Array.Empty<string>());

        var report = new RegressionIsolationService().Isolate(
            "Adjacent", Array.Empty<string>(), P, F, gateway);

        report.Status.Should().Be(RegressionIsolationStatus.NoCandidates);
        report.FirstFailingCommitId.Should().Be(F);
        report.LastPassingCommitId.Should().Be(P);
        report.TestCount.Should().Be(0);
        report.WorstCaseBound.Should().Be(0);
        report.WithinBound.Should().BeTrue();
        gateway.CallCount.Should().Be(0);
    }

    // Stage 1: duplicates removed before bisection (order preserved)
    // seq after dedupe: P0,c1,c2,HEAD | mid=1 pass | mid=2 fail | stop
    [Fact]
    public void Isolate_DuplicateCandidates_ReducedBeforeBisection()
    {
        var gateway = new ScriptedRevisionTestGateway(new[] { "c2" });

        var report = new RegressionIsolationService().Isolate(
            "Dupes", new[] { "c1", "c1", "c2" }, P, F, gateway);

        report.InputCandidateCount.Should().Be(3);
        report.DuplicateCount.Should().Be(1);
        report.CandidateCount.Should().Be(2);
        report.FirstFailingCommitId.Should().Be("c2");
        report.LastPassingCommitId.Should().Be("c1");
        report.TestedCommitIds.Should().ContainInOrder("c1", "c2");
        report.TestCount.Should().Be(2);
        report.WorstCaseBound.Should().Be(2);           // ceil(log2(3))
        report.WithinBound.Should().BeTrue();
    }

    // Single candidate, failing: one test, exact bound
    [Fact]
    public void Isolate_SingleCandidateFailing_OneTestExactBound()
    {
        var gateway = new ScriptedRevisionTestGateway(new[] { "c1" });

        var report = new RegressionIsolationService().Isolate(
            "Single", new[] { "c1" }, P, F, gateway);

        report.FirstFailingCommitId.Should().Be("c1");
        report.LastPassingCommitId.Should().Be(P);
        report.TestCount.Should().Be(1);
        report.WorstCaseBound.Should().Be(1);           // ceil(log2(2))
        report.WithinBound.Should().BeTrue();
    }

    // Single candidate, passing: failure sits at the known-failing boundary
    [Fact]
    public void Isolate_SingleCandidatePassing_BoundaryIsKnownFailing()
    {
        var gateway = new ScriptedRevisionTestGateway(Array.Empty<string>());

        var report = new RegressionIsolationService().Isolate(
            "SinglePass", new[] { "c1" }, P, F, gateway);

        report.FirstFailingCommitId.Should().Be(F);
        report.LastPassingCommitId.Should().Be("c1");
        report.TestCount.Should().Be(1);
    }

    // Contract violations fail fast
    [Fact]
    public void Isolate_NullOrInvalidArguments_Throw()
    {
        var gateway = new ScriptedRevisionTestGateway(Array.Empty<string>());
        var candidates = new[] { "c1" };

        Action nullCandidates = () => new RegressionIsolationService()
            .Isolate("S", null!, P, F, gateway);
        Action nullGateway = () => new RegressionIsolationService()
            .Isolate("S", candidates, P, F, null!);
        Action emptyPassing = () => new RegressionIsolationService()
            .Isolate("S", candidates, " ", F, gateway);
        Action emptyFailing = () => new RegressionIsolationService()
            .Isolate("S", candidates, P, " ", gateway);

        nullCandidates.Should().Throw<ArgumentNullException>();
        nullGateway.Should().Throw<ArgumentNullException>();
        emptyPassing.Should().Throw<ArgumentException>();
        emptyFailing.Should().Throw<ArgumentException>();
    }

    // Research contract markers (serializable disclaimer - 15.7 lesson)
    [Fact]
    public void Report_CarriesResearchMarkers()
    {
        RegressionIsolationReport.DisclaimerText.Should().Contain("EXPERIMENTAL");
        RegressionIsolationReport.DisclaimerText.Should().Contain("never checks out");
        RegressionIsolationReport.DisclaimerText.Should().Contain("monotonic");
    }
}