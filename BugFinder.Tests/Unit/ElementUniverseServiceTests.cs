using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class ElementUniverseServiceTests
{
    private readonly ElementUniverseService _service = new();

    private static CoverageDocument ParsedDocument(
        string artifact, string filePath, params (int Line, int Hits)[] lines)
    {
        var coverageLines = lines.Select(l => new CoverageLine
        {
            LineNumber = l.Line,
            Hits = l.Hits
        }).ToList();

        var cls = new CoverageClass
        {
            ClassName = "NS.Cls",
            SourceFilePath = filePath,
            Methods = Array.Empty<CoverageMethod>(),
            AllLines = coverageLines
        };

        return new CoverageDocument
        {
            Status = CoverageParsingStatus.Parsed,
            SourceArtifactPath = artifact,
            Modules = new[]
            {
                new CoverageModule { ModuleName = "Tests.dll", Classes = new[] { cls } }
            },
            TotalLines = coverageLines.Count,
            CoveredLines = coverageLines.Count(l => l.IsCovered)
        };
    }

    private static CoverageDocument FailedDocument(
        string artifact, CoverageParsingStatus status, string reason) =>
        new() { Status = status, SourceArtifactPath = artifact, Reason = reason };

    private static PerTestCoverage Mapped(
        string test, string artifact, params (string Key, int Hits)[] hits) =>
        new()
        {
            Status = PerTestMappingStatus.Mapped,
            TestFullName = test,
            SourceArtifactPath = artifact,
            ElementHits = hits.ToDictionary(h => h.Key, h => h.Hits, StringComparer.Ordinal)
        };

    private static PerTestCoverage Unmapped(
        string artifact, params (string Key, int Hits)[] hits) =>
        new()
        {
            Status = PerTestMappingStatus.Unmapped,
            SourceArtifactPath = artifact,
            Reason = "unmapped document",
            ElementHits = hits.ToDictionary(h => h.Key, h => h.Hits, StringComparer.Ordinal)
        };

    private static PerTestCoverageReport Report(params PerTestCoverage[] entries) =>
        new() { Entries = entries };

    // THE KBF-06-005 fix — uncovered elements are explicit universe members
    [Fact]
    public void Build_InstrumentedZeroHitLine_IsExplicitUncoveredMember()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 3), (11, 0));
        var spectra = Report(Mapped("NS.A.TestA", "cov.xml",
            ("FILE|A.cs|L10", 3), ("FILE|A.cs|L11", 0)));

        var universe = _service.Build(new[] { doc }, spectra);

        universe.TotalCount.Should().Be(2);   // NOT 1 — the zero-hit line is a member
        universe.UncoveredCount.Should().Be(1);

        var covered = universe.Elements.Single(e => e.LineNumber == 10);
        covered.State.Should().Be(ElementUniverseState.Covered);
        covered.IsInstrumented.Should().BeTrue();
        covered.MaxObservedHits.Should().Be(3);

        var uncovered = universe.Elements.Single(e => e.LineNumber == 11);
        uncovered.State.Should().Be(ElementUniverseState.Uncovered);
        uncovered.IsInstrumented.Should().BeTrue();
        uncovered.MaxObservedHits.Should().Be(0);
    }

    // Stage 4.4.4 — Unknown preserved, never dropped
    [Fact]
    public void Build_ElementInSpectrumAbsentFromMetadata_IsUnknownAndKept()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 3));
        var spectra = Report(Mapped("NS.A.TestA", "cov.xml",
            ("FILE|A.cs|L10", 3), ("FILE|B.cs|L99", 5)));

        var universe = _service.Build(new[] { doc }, spectra);

        universe.UnknownCount.Should().Be(1);
        var unknown = universe.Elements.Single(e => e.State == ElementUniverseState.Unknown);
        unknown.ElementKey.Should().Be("FILE|B.cs|L99");
        unknown.SourceFilePath.Should().Be("B.cs");
        unknown.LineNumber.Should().Be(99);
        unknown.IsInstrumented.Should().BeFalse();
        unknown.MaxObservedHits.Should().Be(5);
    }

    // Stage 4.4.2 — only instrumented elements enter; nothing synthesized
    [Fact]
    public void Build_UniverseContainsOnlyInstrumentedElements_NoSynthesis()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 3), (11, 0));
        var spectra = Report(Mapped("NS.A.TestA", "cov.xml", ("FILE|A.cs|L10", 3)));

        var universe = _service.Build(new[] { doc }, spectra);

        universe.Elements.Select(e => e.ElementKey).Should().BeEquivalentTo(
            new[] { "FILE|A.cs|L10", "FILE|A.cs|L11" });
        universe.UnknownCount.Should().Be(0);
    }

    // Non-Parsed documents: skipped WITH diagnostic, never silently dropped
    [Fact]
    public void Build_NonParsedDocument_SkippedWithDiagnostic()
    {
        var corrupt = FailedDocument("cov-bad.xml", CoverageParsingStatus.Corrupt, "unreadable");
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 3));
        var spectra = Report(Mapped("NS.A.TestA", "cov.xml", ("FILE|A.cs|L10", 3)));

        var universe = _service.Build(new[] { corrupt, doc }, spectra);

        universe.TotalCount.Should().Be(1);
        universe.Diagnostics.Should().Contain(d =>
            d.Contains("cov-bad.xml") && d.Contains("Corrupt"));
        universe.SourceArtifactPaths.Should().BeEquivalentTo(new[] { "cov.xml" });
    }

    // Stage 4.4.5 — deterministic universe (identical inputs, identical order)
    [Fact]
    public void Build_RepeatedInputs_ProduceIdenticalOrdinalUniverse()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (20, 1), (10, 2));   // unsorted input
        var spectra = Report(
            Mapped("NS.A.T1", "cov.xml", ("FILE|A.cs|L10", 2)),
            Mapped("NS.A.T2", "cov.xml", ("FILE|A.cs|L20", 1), ("FILE|B.cs|L99", 4)));

        var first = _service.Build(new[] { doc }, spectra);
        var second = _service.Build(new[] { doc }, spectra);

        first.Elements.Select(e => e.ElementKey).Should().Equal(
            second.Elements.Select(e => e.ElementKey));
        first.Elements.Select(e => e.ElementKey)
            .Should().BeInAscendingOrder(StringComparer.Ordinal);
    }

    // Attribution honesty — unmapped hits never mark Covered
    [Fact]
    public void Build_UnmappedSpectrumHits_NeverAttributeCoverage()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 0));
        var spectra = Report(Unmapped("cov.xml", ("FILE|A.cs|L10", 9)));

        var universe = _service.Build(new[] { doc }, spectra);

        var element = universe.Elements.Single();
        element.State.Should().Be(ElementUniverseState.Uncovered);
        element.MaxObservedHits.Should().Be(0);
    }

    // MaxObservedHits = max across mapped spectra (derived from formula)
    [Fact]
    public void Build_MaxObservedHits_IsMaxAcrossMappedSpectra()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 0));
        var spectra = Report(
            Mapped("NS.A.T1", "cov.xml", ("FILE|A.cs|L10", 3)),
            Mapped("NS.A.T2", "cov.xml", ("FILE|A.cs|L10", 7)));

        var universe = _service.Build(new[] { doc }, spectra);

        var element = universe.Elements.Single();
        element.State.Should().Be(ElementUniverseState.Covered);
        element.MaxObservedHits.Should().Be(7);
    }

    // Malformed external spectrum key: preserved in diagnostics, not in universe
    [Fact]
    public void Build_MalformedSpectrumKey_PreservedInDiagnosticsNotUniverse()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 3));
        var spectra = Report(Mapped("NS.A.TestA", "cov.xml",
            ("FILE|A.cs|L10", 3), ("BOGUS", 1)));

        var universe = _service.Build(new[] { doc }, spectra);

        universe.TotalCount.Should().Be(1);
        universe.Diagnostics.Should().Contain(d => d.Contains("BOGUS"));
    }

    // Empty input = honest empty universe with diagnostic (empty != zero)
    [Fact]
    public void Build_NoDocuments_EmptyUniverseWithDiagnostic()
    {
        var universe = _service.Build(Array.Empty<CoverageDocument>(), Report());

        universe.TotalCount.Should().Be(0);
        universe.Diagnostics.Should().Contain(d => d.Contains("no coverage documents"));
    }

    // H-01.8 boundary — null inputs fail fast
    [Fact]
    public void Build_NullInputs_FailFast()
    {
        var doc = ParsedDocument("cov.xml", "A.cs", (10, 0));

        Action act1 = () => _service.Build(null!, Report());
        Action act2 = () => _service.Build(new[] { doc }, null!);

        act1.Should().Throw<ArgumentNullException>();
        act2.Should().Throw<ArgumentNullException>();
    }
}