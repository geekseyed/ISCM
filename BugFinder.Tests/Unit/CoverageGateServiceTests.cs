using System;
using System.Collections.Generic;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CoverageGateServiceTests
{
    private readonly CoverageGateService _gate = new();

    // ---------- compact builders (MANUAL in-memory evidence; the REAL
    // artifact proof is the separate --collect run, not unit fixtures) ----------
    // NOTE (CS8858 lesson): CoverageGateInput/CoverageDocument are sealed
    // CLASSES — no `with` expressions. Composition is explicit via Compose():
    // every negative test states exactly which evidence is absent/invalid.

    private const string ArtifactPath = "d:/evidence/coverage.cobertura.xml";

    private static CoverageCollectionEvidence Collection() => new()
    {
        Status = CoverageCollectionStatus.Collected,
        ArtifactPath = ArtifactPath,
        ArtifactExists = true
    };

    private static CoverageDocument Document(
        CoverageParsingStatus status = CoverageParsingStatus.Parsed,
        string path = ArtifactPath) => new()
        {
            Status = status,
            SourceArtifactPath = path,
            Reason = status == CoverageParsingStatus.Parsed ? string.Empty : "forced failure"
        };

    private static PerTestCoverageReport Mapping(int mapped = 1) => new()
    {
        Entries = new[]
        {
            new PerTestCoverage
            {
                Status = PerTestMappingStatus.Mapped,
                TestFullName = "NS.T1",
                ElementHits = new Dictionary<string, int> { ["FILE|A.cs|L10"] = 1 }
            }
        },
        MappedCount = mapped
    };

    private static PassFailSpectrumReport Spectrum(
        TrxIngestionStatus status = TrxIngestionStatus.Ingested,
        int unknown = 0,
        bool withElements = true) =>
        new()
        {
            SourceStatus = status,
            SourceArtifactPath = "run.trx",
            TestOutcomes = BuildOutcomes(unknown),
            Elements = withElements
                ? new[]
                {
                    new ElementOutcomeSpectrum
                    {
                        ElementKey = "FILE|A.cs|L10", PassedHitCount = 1, FailedHitCount = 1
                    }
                }
                : Array.Empty<ElementOutcomeSpectrum>()
        };

    private static IReadOnlyList<TestOutcomeClassification> BuildOutcomes(int unknown)
    {
        var outcomes = new List<TestOutcomeClassification>
        {
            new() { TestFullName = "NS.P", RawOutcome = "Passed", Outcome = SpectrumTestOutcome.Passed },
            new() { TestFullName = "NS.F", RawOutcome = "Failed", Outcome = SpectrumTestOutcome.Failed }
        };
        for (var i = 0; i < unknown; i++)
            outcomes.Add(new TestOutcomeClassification
            {
                TestFullName = $"NS.U{i}",
                RawOutcome = "Bogus",
                Outcome = SpectrumTestOutcome.Unknown
            });
        return outcomes;
    }

    private static DomainCoverageReport Domain(
        DomainResultIngestionStatus status = DomainResultIngestionStatus.Ingested,
        int unresolved = 0, int ambiguous = 0) => new()
        {
            SourceStatus = status,
            CorrelatedCount = 1 - unresolved - ambiguous,
            UnresolvedCount = unresolved,
            AmbiguousCount = ambiguous
        };

    private static CoverageProvenanceRecord Provenance(
        CoverageProvenanceStatus status = CoverageProvenanceStatus.Recorded,
        bool testSet = true, bool mapping = true) => new()
        {
            Status = status,
            HasTestSet = testSet,
            HasMappingCompleteness = mapping
        };

    /// <summary>Explicit composition — the gate's evidence bowl.</summary>
    private static CoverageGateInput Compose(
        CoverageCollectionEvidence? collection,
        CoverageDocument? document,
        PerTestCoverageReport? mapping,
        PassFailSpectrumReport? spectrum,
        DomainCoverageReport? domain,
        CoverageProvenanceRecord? provenance) => new()
        {
            Collection = collection,
            Document = document,
            Mapping = mapping,
            Spectrum = spectrum,
            Domain = domain,
            Provenance = provenance
        };

    /// <summary>Every stage supplied and valid.</summary>
    private static CoverageGateInput GreenValid() => Compose(
        Collection(), Document(), Mapping(), Spectrum(), Domain(), Provenance());

    // 1 — all valid -> PASS and BF-12 enabled
    [Fact]
    public void Evaluate_AllValid_PassesAndEnablesBf12()
    {
        var report = _gate.Evaluate(GreenValid());

        report.Verdict.Should().Be(CoverageGateVerdict.Pass);
        report.BlockReasons.Should().BeEmpty();
        report.IsBf12Enabled.Should().BeTrue();
        report.Stages.Should().HaveCount(5);
        report.Stages.Should().OnlyContain(s => s.Passed);
    }

    // 2 — artifact missing (collection evidence absent) -> BLOCKED
    [Fact]
    public void Evaluate_CollectionEvidenceMissing_Blocks()
    {
        var report = _gate.Evaluate(Compose(
            null, Document(), Mapping(), Spectrum(), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Blocked);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.CollectionEvidenceMissing);
        report.IsBf12Enabled.Should().BeFalse();
    }

    // 3 — artifact invalid (corrupt) -> FAIL
    [Fact]
    public void Evaluate_CorruptArtifact_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(CoverageParsingStatus.Corrupt),
            Mapping(), Spectrum(), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.CoverageArtifactCorrupt);
        report.IsBf12Enabled.Should().BeFalse();
    }

    // 3b — run-to-artifact binding broken -> FAIL (the KBF-06-010 binding evidence)
    [Fact]
    public void Evaluate_UnboundArtifactPath_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(path: "d:/evidence/other-run.xml"),
            Mapping(), Spectrum(), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.ArtifactPathUnbound);
    }

    // 4 — mapping unavailable -> BLOCKED; zero mapped -> FAIL
    [Fact]
    public void Evaluate_MappingUnavailableOrIncomplete_BlocksOrFails()
    {
        var blocked = _gate.Evaluate(Compose(
            Collection(), Document(), null, Spectrum(), Domain(), Provenance()));
        blocked.Verdict.Should().Be(CoverageGateVerdict.Blocked);
        blocked.BlockReasons.Should().Contain(CoverageGateBlockReason.TestToCodeMappingUnavailable);

        var failed = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(mapped: 0), Spectrum(), Domain(), Provenance()));
        failed.Verdict.Should().Be(CoverageGateVerdict.Fail);
        failed.BlockReasons.Should().Contain(CoverageGateBlockReason.TestToCodeMappingIncomplete);
    }

    // 5 — TRX not ingested -> FAIL (zero failures would be fabricated)
    [Fact]
    public void Evaluate_TrxNotIngested_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(),
            Spectrum(status: TrxIngestionStatus.NoResults), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.TestSourceNotIngested);
    }

    // 5b — UNKNOWN outcome can NEVER become PASS (strict policy)
    [Fact]
    public void Evaluate_UnclassifiedOutcomes_Fail()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(), Spectrum(unknown: 1), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.UnclassifiedTestOutcomes);
        report.IsBf12Enabled.Should().BeFalse();
    }

    // 5c — empty element spectrum: nothing for BF-12 to rank
    [Fact]
    public void Evaluate_ElementSpectrumEmpty_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(), Spectrum(withElements: false), Domain(), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.ElementSpectrumEmpty);
    }

    // 6 — domain unresolved/ambiguous = honest states (NOT blockers, NEVER NotCovered)
    [Fact]
    public void Evaluate_DomainUnresolved_RecordsHonestStateNotBlocker()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(),
            Spectrum(), Domain(unresolved: 1, ambiguous: 1), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Pass);
        report.IsBf12Enabled.Should().BeTrue();
        report.Diagnostics.Should().Contain(d =>
            d.Contains("unresolved=1") && d.Contains("NEVER inferred as NotCovered"));
    }

    // 6b — domain supplied but not ingested -> FAIL (no silent "no signal")
    [Fact]
    public void Evaluate_DomainSourceNotIngested_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(),
            Spectrum(), Domain(status: DomainResultIngestionStatus.Corrupt), Provenance()));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.DomainSourceNotIngested);
    }

    // 7 — provenance incomplete -> FAIL per policy
    [Fact]
    public void Evaluate_ProvenanceIncomplete_Fails()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(), Spectrum(),
            Domain(), Provenance(mapping: false)));

        report.Verdict.Should().Be(CoverageGateVerdict.Fail);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.ProvenanceIncomplete);
    }

    // 7b — provenance missing -> BLOCKED
    [Fact]
    public void Evaluate_ProvenanceMissing_Blocks()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), Mapping(), Spectrum(), Domain(), null));

        report.Verdict.Should().Be(CoverageGateVerdict.Blocked);
        report.BlockReasons.Should().Contain(CoverageGateBlockReason.ProvenanceUnavailable);
    }

    // 9 — BF-12 CANNOT bypass a failed gate (enforcement API throws with reasons)
    [Fact]
    public void EnsureBf12Authorized_WhenNotPassed_ThrowsWithReasons()
    {
        var report = _gate.Evaluate(Compose(
            Collection(), Document(), null, Spectrum(), Domain(), Provenance()));

        report.IsBf12Enabled.Should().BeFalse();
        Action bypass = () => report.EnsureBf12Authorized();
        bypass.Should().Throw<InvalidOperationException>()
            .And.Message.Should().Contain("BF-12").And.Contain("TestToCodeMappingUnavailable");
    }

    // 10 — BF-12 enabled ONLY through the gate (PASS returns the report)
    [Fact]
    public void EnsureBf12Authorized_WhenPassed_ReturnsReport()
    {
        var report = _gate.Evaluate(GreenValid());

        report.EnsureBf12Authorized().Should().BeSameAs(report);
    }

    // determinism — identical inputs -> identical verdict + reason order
    [Fact]
    public void Evaluate_RepeatedInputs_DeterministicVerdict()
    {
        var first = _gate.Evaluate(Compose(
            Collection(), Document(), null, null, Domain(), Provenance()));
        var second = _gate.Evaluate(Compose(
            Collection(), Document(), null, null, Domain(), Provenance()));

        first.Verdict.Should().Be(second.Verdict);
        first.BlockReasons.Should().Equal(second.BlockReasons);
    }

    // H-01.8 — null input object fails fast
    [Fact]
    public void Evaluate_NullInput_FailFast()
    {
        Action act = () => _gate.Evaluate(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}