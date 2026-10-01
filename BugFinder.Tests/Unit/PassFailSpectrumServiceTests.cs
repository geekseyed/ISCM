using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class PassFailSpectrumServiceTests
{
    private readonly PassFailSpectrumService _service = new();

    private static TrxIngestionReport Trx(
        string artifact, params (string Name, string Outcome, string Assembly)[] records) =>
        new()
        {
            Status = TrxIngestionStatus.Ingested,
            SourceArtifactPath = artifact,
            Records = records.Select(r => new TrxTestRecord
            {
                TestFullName = r.Name,
                Outcome = r.Outcome,
                AssemblyPath = r.Assembly
            }).ToList()
        };

    private static PerTestCoverage Mapped(
        string test, params (string Key, int Hits)[] hits) =>
        new()
        {
            Status = PerTestMappingStatus.Mapped,
            TestFullName = test,
            SourceArtifactPath = "cov.xml",
            ElementHits = hits.ToDictionary(h => h.Key, h => h.Hits, StringComparer.Ordinal)
        };

    private static PerTestCoverageReport SpectrumReport(params PerTestCoverage[] entries) =>
        new() { Entries = entries };

    // documented outcome mapping (test-pinned) — 4.5.1..4.5.4 vocabulary
    [Theory]
    [InlineData("Passed", SpectrumTestOutcome.Passed)]
    [InlineData("Failed", SpectrumTestOutcome.Failed)]
    [InlineData("Error", SpectrumTestOutcome.Error)]
    [InlineData("Timeout", SpectrumTestOutcome.Error)]
    [InlineData("NotExecuted", SpectrumTestOutcome.Skipped)]
    [InlineData("Skipped", SpectrumTestOutcome.Skipped)]
    [InlineData("NotRunnable", SpectrumTestOutcome.Unavailable)]
    [InlineData("Disconnected", SpectrumTestOutcome.Unavailable)]
    public void ClassifyOutcome_KnownVocabulary_MapsExplicitly(string raw, SpectrumTestOutcome expected)
    {
        PassFailSpectrumService.ClassifyOutcome(raw).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("BogusOutcome")]
    [InlineData("Inconclusive")]
    public void ClassifyOutcome_Unrecognized_IsUnknownNeverGuessed(string raw)
    {
        PassFailSpectrumService.ClassifyOutcome(raw).Should().Be(SpectrumTestOutcome.Unknown);
    }

    // THE KBF-06-004 fix — skipped is NOT counted as failed; an element
    // executed ONLY by skipped tests has NO attributed execution and is
    // ABSENT from the outcome spectrum (not present with fake zeros —
    // its instrumented state lives in the H-04.4 universe).
    [Fact]
    public void Build_SkippedTest_IsNotCountedAsFailed()
    {
        var trx = Trx("run.trx",
            ("NS.T1", "Passed", "a.dll"),
            ("NS.T2", "NotExecuted", "a.dll"),
            ("NS.T3", "Failed", "a.dll"));
        var spectra = SpectrumReport(
            Mapped("NS.T1", ("FILE|A.cs|L10", 1)),
            Mapped("NS.T2", ("FILE|A.cs|L11", 2)),
            Mapped("NS.T3", ("FILE|A.cs|L12", 3)));

        var report = _service.Build(trx, spectra);

        report.PassedTestCount.Should().Be(1);
        report.SkippedTestCount.Should().Be(1);
        report.FailedTestCount.Should().Be(1);
        report.UnknownTestCount.Should().Be(0);

        report.Elements.Select(e => e.ElementKey).Should().BeEquivalentTo(
            new[] { "FILE|A.cs|L10", "FILE|A.cs|L12" });
        report.Elements.Should().NotContain(e => e.ElementKey == "FILE|A.cs|L11");
        report.Diagnostics.Should().Contain(d => d.Contains("NS.T2") && d.Contains("Skipped"));
    }

    // element counters separated by outcome class (aep/aef raw material)
    [Fact]
    public void Build_ElementCounters_AreSeparatedByOutcomeClass()
    {
        var trx = Trx("run.trx",
            ("NS.P1", "Passed", "a.dll"),
            ("NS.P2", "Passed", "a.dll"),
            ("NS.F1", "Failed", "a.dll"));
        var spectra = SpectrumReport(
            Mapped("NS.P1", ("FILE|A.cs|L10", 1)),
            Mapped("NS.P2", ("FILE|A.cs|L10", 1), ("FILE|A.cs|L20", 1)),
            Mapped("NS.F1", ("FILE|A.cs|L10", 1), ("FILE|A.cs|L20", 1)));

        var report = _service.Build(trx, spectra);

        var l10 = report.Elements.Single(e => e.ElementKey == "FILE|A.cs|L10");
        l10.PassedHitCount.Should().Be(2);
        l10.FailedHitCount.Should().Be(1);

        var l20 = report.Elements.Single(e => e.ElementKey == "FILE|A.cs|L20");
        l20.PassedHitCount.Should().Be(1);
        l20.FailedHitCount.Should().Be(1);
    }

    // 4.5.3 — error is a separate bucket, never merged into failed
    [Fact]
    public void Build_ErrorOutcome_GetsSeparateCounter()
    {
        var trx = Trx("run.trx", ("NS.E1", "Error", "a.dll"));
        var spectra = SpectrumReport(Mapped("NS.E1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        report.ErrorTestCount.Should().Be(1);
        report.FailedTestCount.Should().Be(0);
        var element = report.Elements.Single();
        element.ErrorHitCount.Should().Be(1);
        element.FailedHitCount.Should().Be(0);
    }

    // 4.5.4 — unavailable execution excluded, never failed
    [Fact]
    public void Build_UnavailableOutcome_IsExcludedFromElementSpectrum()
    {
        var trx = Trx("run.trx", ("NS.U1", "NotRunnable", "a.dll"));
        var spectra = SpectrumReport(Mapped("NS.U1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        report.UnavailableTestCount.Should().Be(1);
        report.Elements.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d =>
            d.Contains("NotRunnable") || d.Contains("Unavailable"));
    }

    // 4.5.5 — provenance preserved per test
    [Fact]
    public void Build_OutcomeProvenance_PreservedPerTest()
    {
        var trx = Trx("d:/run/run.trx", ("NS.T1", "Failed", "d:/out/a.dll"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        var classification = report.TestOutcomes.Single();
        classification.RawOutcome.Should().Be("Failed");
        classification.TrxArtifactPath.Should().Be("d:/run/run.trx");
        classification.AssemblyPath.Should().Be("d:/out/a.dll");
        report.SourceArtifactPath.Should().Be("d:/run/run.trx");
    }

    // absent raw outcome → Unknown (never guessed), raw verbatim empty
    [Fact]
    public void Build_AbsentRawOutcome_ClassifiedUnknownWithVerbatimEmpty()
    {
        var trx = Trx("run.trx", ("NS.T1", "", "a.dll"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        report.UnknownTestCount.Should().Be(1);
        report.TestOutcomes.Single().RawOutcome.Should().Be(string.Empty);
        report.Elements.Should().BeEmpty();
    }

    // zero-hit elements contribute nothing to counters
    [Fact]
    public void Build_ZeroHitElements_AreNotCounted()
    {
        var trx = Trx("run.trx", ("NS.T1", "Passed", "a.dll"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 3), ("FILE|A.cs|L11", 0)));

        var report = _service.Build(trx, spectra);

        report.Elements.Select(e => e.ElementKey)
            .Should().BeEquivalentTo(new[] { "FILE|A.cs|L10" });
    }

    // duplicate name + conflicting outcomes → ambiguous, excluded (never picks one)
    [Fact]
    public void Build_ConflictingDuplicateNames_AreExcludedWithDiagnostic()
    {
        var trx = Trx("run.trx",
            ("NS.Dup", "Passed", "a.dll"),
            ("NS.Dup", "Failed", "a.dll"));
        var spectra = SpectrumReport(Mapped("NS.Dup", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        report.Elements.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d => d.Contains("ambiguous") && d.Contains("NS.Dup"));
    }

    // unmapped spectrum documents never enter element counters
    [Fact]
    public void Build_UnmappedSpectrumEntries_AreIgnored()
    {
        var trx = Trx("run.trx", ("NS.T1", "Passed", "a.dll"));
        var unmapped = new PerTestCoverage
        {
            Status = PerTestMappingStatus.Unmapped,
            SourceArtifactPath = "cov-orphan.xml",
            Reason = "no matching TRX record",
            ElementHits = new Dictionary<string, int> { ["FILE|X.cs|L1"] = 9 }
        };
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)), unmapped);

        var report = _service.Build(trx, spectra);

        report.Elements.Select(e => e.ElementKey)
            .Should().BeEquivalentTo(new[] { "FILE|A.cs|L10" });
    }

    // TRX not ingested → honest empty report, nothing fabricated
    [Fact]
    public void Build_TrxNotIngested_NoOutcomesFabricated()
    {
        var trx = new TrxIngestionReport
        {
            Status = TrxIngestionStatus.Corrupt,
            SourceArtifactPath = "run.trx",
            Reason = "unreadable XML"
        };
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(trx, spectra);

        report.SourceStatus.Should().Be(TrxIngestionStatus.Corrupt);
        report.TestOutcomes.Should().BeEmpty();
        report.Elements.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d => d.Contains("Corrupt"));
    }

    // determinism — identical inputs → identical ordinal ordering
    [Fact]
    public void Build_RepeatedInputs_DeterministicOrdinalOrder()
    {
        var trx = Trx("run.trx",
            ("NS.B", "Failed", "a.dll"),
            ("NS.A", "Passed", "a.dll"));
        var spectra = SpectrumReport(
            Mapped("NS.B", ("FILE|B.cs|L1", 1)),
            Mapped("NS.A", ("FILE|A.cs|L1", 1)));

        var first = _service.Build(trx, spectra);
        var second = _service.Build(trx, spectra);

        first.Elements.Select(e => e.ElementKey)
            .Should().Equal(second.Elements.Select(e => e.ElementKey));
        first.TestOutcomes.Select(t => t.TestFullName)
            .Should().BeInAscendingOrder(StringComparer.Ordinal);
        first.Elements.Select(e => e.ElementKey)
            .Should().BeInAscendingOrder(StringComparer.Ordinal);
    }

    // H-01.8 — null inputs fail fast
    [Fact]
    public void Build_NullInputs_FailFast()
    {
        var trx = Trx("run.trx", ("NS.T1", "Passed", "a.dll"));

        Action act1 = () => _service.Build(null!, SpectrumReport());
        Action act2 = () => _service.Build(trx, null!);

        act1.Should().Throw<ArgumentNullException>();
        act2.Should().Throw<ArgumentNullException>();
    }
}