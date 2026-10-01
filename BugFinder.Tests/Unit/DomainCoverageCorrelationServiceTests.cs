using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class DomainCoverageCorrelationServiceTests
{
    private readonly DomainCoverageCorrelationService _service = new();

    private static DomainEvaluationRecord Record(
        string subControlId, CheckStatus status = CheckStatus.Fail,
        string? rawStatus = "Fail", string? sourceTestId = null, string? reason = null) =>
        new()
        {
            SubControlId = subControlId,
            Status = status,
            RawStatus = rawStatus,
            Reason = reason,
            SourceTestId = sourceTestId
        };

    private static DomainResultIngestionReport DomainReport(
        params DomainEvaluationRecord[] records) =>
        new()
        {
            Status = DomainResultIngestionStatus.Ingested,
            SourceArtifactPath = "domain-results.json",
            Records = records
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

    private static PerTestCoverage MissingCoverage(string test) =>
        new()
        {
            Status = PerTestMappingStatus.MissingCoverage,
            TestFullName = test,
            SourceArtifactPath = "missing",
            Reason = "no coverage document available for this test"
        };

    private static PerTestCoverageReport SpectrumReport(params PerTestCoverage[] entries) =>
        new() { Entries = entries };

    // 4.6.3 — exact identity match, covered = executed (hits>0) only
    [Fact]
    public void Build_ExactMatch_CorrelatesWithExecutedElements()
    {
        var domain = DomainReport(Record("EVL-001.4", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(Mapped("NS.T1",
            ("FILE|A.cs|L10", 3), ("FILE|A.cs|L11", 0), ("FILE|A.cs|L12", 2)));

        var report = _service.Build(domain, spectra);

        report.CorrelatedCount.Should().Be(1);
        var correlation = report.Correlations.Single();
        correlation.State.Should().Be(DomainCorrelationState.Correlated);
        correlation.MatchKind.Should().Be(DomainCorrelationMatchKind.Exact);
        correlation.MatchedTestFullName.Should().Be("NS.T1");
        correlation.MatchedTestHasCoverageSpectrum.Should().BeTrue();
        correlation.CoveredElementKeys.Should().Equal(
            new[] { "FILE|A.cs|L10", "FILE|A.cs|L12" });   // L11 zero-hit excluded
    }

    // 4.6.4 — unambiguous dotted suffix correlates
    [Fact]
    public void Build_DottedSuffix_Unambiguous_Correlates()
    {
        var domain = DomainReport(Record("EVL-002", sourceTestId: "LoginTest"));
        var spectra = SpectrumReport(Mapped("ISCM.Tests.Unit.LoginTest",
            ("FILE|B.cs|L5", 1)));

        var report = _service.Build(domain, spectra);

        var correlation = report.Correlations.Single();
        correlation.State.Should().Be(DomainCorrelationState.Correlated);
        correlation.MatchKind.Should().Be(DomainCorrelationMatchKind.DottedSuffix);
        correlation.MatchedTestFullName.Should().Be("ISCM.Tests.Unit.LoginTest");
        correlation.CoveredElementKeys.Should().Equal(new[] { "FILE|B.cs|L5" });
    }

    // 4.6.5 — multiple suffix candidates: Ambiguous, none picked
    [Fact]
    public void Build_DottedSuffix_MultipleCandidates_AmbiguousNotPicked()
    {
        var domain = DomainReport(Record("EVL-003", sourceTestId: "RunTest"));
        var spectra = SpectrumReport(
            Mapped("B.Module.RunTest", ("FILE|B.cs|L1", 1)),
            Mapped("A.Module.RunTest", ("FILE|A.cs|L1", 1)));

        var report = _service.Build(domain, spectra);

        report.AmbiguousCount.Should().Be(1);
        report.CorrelatedCount.Should().Be(0);
        var correlation = report.Correlations.Single();
        correlation.State.Should().Be(DomainCorrelationState.Ambiguous);
        correlation.MatchedTestFullName.Should().BeNull();
        correlation.AmbiguousCandidates.Should().Equal(
            new[] { "A.Module.RunTest", "B.Module.RunTest" });   // ordinal
        correlation.CoveredElementKeys.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d => d.Contains("Ambiguous") && d.Contains("RunTest"));
    }

    // 4.6.1 — absent SourceTestId: Unresolved, never guessed
    [Fact]
    public void Build_AbsentSourceTestId_UnresolvedNeverGuessed()
    {
        var domain = DomainReport(Record("EVL-004", sourceTestId: null));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        report.UnresolvedCount.Should().Be(1);
        var correlation = report.Correlations.Single();
        correlation.State.Should().Be(DomainCorrelationState.Unresolved);
        correlation.MatchedTestFullName.Should().BeNull();
        report.Diagnostics.Should().Contain(d =>
            d.Contains("SourceTestId absent") && d.Contains("EVL-004"));
    }

    // 4.6.5 — no matching test: Unresolved
    [Fact]
    public void Build_NoMatchingTest_Unresolved()
    {
        var domain = DomainReport(Record("EVL-005", sourceTestId: "Ghost_Test"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        report.UnresolvedCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d =>
            d.Contains("no test matches") && d.Contains("Ghost_Test"));
    }

    // H-01.4 — matched but no mapped spectrum: correlated with ZERO elements
    // + diagnostic (missing coverage != zero coverage)
    [Fact]
    public void Build_MatchedTestWithoutMappedSpectrum_ZeroElementsWithDiagnostic()
    {
        var domain = DomainReport(Record("EVL-006", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(MissingCoverage("NS.T1"));

        var report = _service.Build(domain, spectra);

        var correlation = report.Correlations.Single();
        correlation.State.Should().Be(DomainCorrelationState.Correlated);
        correlation.MatchedTestFullName.Should().Be("NS.T1");
        correlation.MatchedTestHasCoverageSpectrum.Should().BeFalse();
        correlation.CoveredElementKeys.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d =>
            d.Contains("no mapped coverage spectrum") && d.Contains("NS.T1"));
    }

    // H-03.8.5 continuity — domain status semantics preserved verbatim
    [Fact]
    public void Build_StatusAndRawStatus_PreservedVerbatim()
    {
        var domain = DomainReport(
            Record("EVL-007a", CheckStatus.Fail, "Fail", "NS.T1"),
            Record("EVL-007b", CheckStatus.Unknown, "WeirdStatus", "NS.T1"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        var first = report.Correlations.First(c => c.SubControlId == "EVL-007a");
        first.Status.Should().Be(CheckStatus.Fail);
        first.RawStatus.Should().Be("Fail");

        var second = report.Correlations.First(c => c.SubControlId == "EVL-007b");
        second.Status.Should().Be(CheckStatus.Unknown);
        second.RawStatus.Should().Be("WeirdStatus");
    }

    // Honest gate — non-ingested source: nothing fabricated
    [Fact]
    public void Build_SourceNotIngested_NothingFabricated()
    {
        var domain = new DomainResultIngestionReport
        {
            Status = DomainResultIngestionStatus.Corrupt,
            SourceArtifactPath = "bad.json",
            Reason = "unreadable JSON"
        };
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        report.SourceStatus.Should().Be(DomainResultIngestionStatus.Corrupt);
        report.Correlations.Should().BeEmpty();
        report.Diagnostics.Should().Contain(d => d.Contains("Corrupt") && d.Contains("bad.json"));
    }

    // Exact match wins over dotted-suffix candidates
    [Fact]
    public void Build_ExactPreferredOverDottedSuffix()
    {
        var domain = DomainReport(Record("EVL-008", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(
            Mapped("NS.T1", ("FILE|A.cs|L10", 1)),
            Mapped("A.NS.T1", ("FILE|B.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        var correlation = report.Correlations.Single();
        correlation.MatchKind.Should().Be(DomainCorrelationMatchKind.Exact);
        correlation.MatchedTestFullName.Should().Be("NS.T1");
        correlation.CoveredElementKeys.Should().Equal(new[] { "FILE|A.cs|L10" });
    }

    // Duplicate test names (same logical test) — union of covered elements
    [Fact]
    public void Build_DuplicateTestNames_UnionCoveredElements()
    {
        var domain = DomainReport(Record("EVL-009", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(
            Mapped("NS.T1", ("FILE|A.cs|L10", 3)),
            Mapped("NS.T1", ("FILE|A.cs|L10", 5), ("FILE|A.cs|L20", 1)));

        var report = _service.Build(domain, spectra);

        var correlation = report.Correlations.Single();
        correlation.CoveredElementKeys.Should().Equal(
            new[] { "FILE|A.cs|L10", "FILE|A.cs|L20" });
    }

    // Empty-name spectrum entries (unmapped documents) diagnosed, join unaffected
    [Fact]
    public void Build_EmptyTestFullNameEntry_DiagnosedAndExcluded()
    {
        var domain = DomainReport(Record("EVL-010", sourceTestId: "NS.T1"));
        var unmapped = new PerTestCoverage
        {
            Status = PerTestMappingStatus.Unmapped,
            SourceArtifactPath = "cov-orphan.xml",
            Reason = "no matching TRX record"
        };
        var spectra = SpectrumReport(unmapped, Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        report.CorrelatedCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("empty TestFullName"));
    }

    // Deterministic — identical inputs produce identical ordinal-ordered report
    [Fact]
    public void Build_TwoRuns_IdenticalOrdinalReport()
    {
        var domain = DomainReport(
            Record("EVL-B", sourceTestId: "NS.T2"),
            Record("EVL-A", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(
            Mapped("NS.T2", ("FILE|B.cs|L1", 1)),
            Mapped("NS.T1", ("FILE|A.cs|L1", 1)));

        var first = _service.Build(domain, spectra);
        var second = _service.Build(domain, spectra);

        first.Correlations.Select(c => c.SubControlId)
            .Should().Equal(second.Correlations.Select(c => c.SubControlId));
        first.Correlations.Select(c => c.SubControlId)
            .Should().BeInAscendingOrder(StringComparer.Ordinal);
    }

    // Correlation is per record — same SourceTestId twice correlates twice
    [Fact]
    public void Build_MultipleRecordsSameSourceTestId_IndependentlyCorrelated()
    {
        var domain = DomainReport(
            Record("EVL-011a", sourceTestId: "NS.T1"),
            Record("EVL-011b", sourceTestId: "NS.T1"));
        var spectra = SpectrumReport(Mapped("NS.T1", ("FILE|A.cs|L10", 1)));

        var report = _service.Build(domain, spectra);

        report.CorrelatedCount.Should().Be(2);
        report.Correlations.Should().OnlyContain(c =>
            c.MatchedTestFullName == "NS.T1" &&
            c.State == DomainCorrelationState.Correlated);
    }

    // H-01.8 — null inputs fail fast
    [Fact]
    public void Build_NullInputs_FailFast()
    {
        var domain = DomainReport(Record("EVL-001", sourceTestId: "NS.T1"));

        Action act1 = () => _service.Build(null!, SpectrumReport());
        Action act2 = () => _service.Build(domain, null!);

        act1.Should().Throw<ArgumentNullException>();
        act2.Should().Throw<ArgumentNullException>();
    }
}