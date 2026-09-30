using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class PerTestCoverageMapperTests
{
    private readonly PerTestCoverageMapper _mapper = new();

    private static CoverageDocument Document(
        string artifact, string className, string filePath,
        params (int Line, int Hits)[] lines)
    {
        var coverageLines = lines.Select(l => new CoverageLine
        {
            LineNumber = l.Line,
            Hits = l.Hits
        }).ToList();

        var method = new CoverageMethod
        {
            MethodName = "Run",
            Signature = "()",
            Lines = coverageLines
        };

        var cls = new CoverageClass
        {
            ClassName = className,
            SourceFilePath = filePath,
            Methods = new[] { method },
            AllLines = coverageLines
        };

        return new CoverageDocument
        {
            Status = CoverageParsingStatus.Parsed,
            SourceArtifactPath = artifact,
            Modules = new[]
            {
                new CoverageModule
                {
                    ModuleName = "Tests.dll",
                    Classes = new[] { cls }
                }
            },
            TotalModules = 1,
            TotalClasses = 1,
            TotalMethods = 1,
            TotalLines = coverageLines.Count,
            CoveredLines = coverageLines.Count(l => l.IsCovered)
        };
    }

    private static TrxTestRecord Record(string fullName) => new()
    {
        ExecutionId = $"guid-{fullName.GetHashCode():X}",
        TestName = fullName.Split('.').Last(),
        TestFullName = fullName,
        AssemblyPath = "d:/out/Tests.dll",
        Outcome = "Failed"
    };

    // THE KBF-06-003 scenario — per-test spectra from real documents
    [Fact]
    public void Map_TwoTestsTwoDocuments_IndependentSpectra()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs",
            (10, 3), (11, 0));
        var docB = Document("cov-B.xml", "NS.B", "B.cs",
            (20, 5));

        var records = new[] { Record("NS.A.TestA"), Record("NS.B.TestB") };
        var report = _mapper.Map(new[] { docA, docB }, records);

        report.MappedCount.Should().Be(2);
        report.Entries.Should().HaveCount(2);

        var entryA = report.Entries.First(e => e.TestFullName == "NS.A.TestA");
        entryA.ElementHits.Should().ContainKey("FILE|A.cs|L10");
        entryA.ElementHits["FILE|A.cs|L10"].Should().Be(3);
        entryA.ElementHits["FILE|A.cs|L11"].Should().Be(0);   // instrumented, not hit

        var entryB = report.Entries.First(e => e.TestFullName == "NS.B.TestB");
        entryB.ElementHits.Should().ContainKey("FILE|B.cs|L20");
    }

    // ElementKey format — H-01.7 normalized (FILE|path|L<line>)
    [Fact]
    public void Map_ElementKeyFormat_H01_7_Compatible()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs", (10, 3));
        var report = _mapper.Map(new[] { docA }, new[] { Record("NS.A.TestA") });

        var entry = report.Entries[0];
        entry.ElementHits.Keys.Should().Contain("FILE|A.cs|L10");
        entry.ElementHits.Keys.Should().OnlyContain(k => k.StartsWith("FILE|"));
    }

    // Spectrum independence — spectra never merge across tests
    [Fact]
    public void Map_Spectra_NeverMerge()
    {
        var docA = Document("cov-A.xml", "NS.Shared", "Shared.cs", (10, 3));
        var docB = Document("cov-B.xml", "NS.Shared", "Shared.cs", (10, 7));

        var report = _mapper.Map(new[] { docA, docB },
            new[] { Record("NS.Shared.TestA"), Record("NS.Shared.TestB") });

        report.Entries.First(e => e.TestFullName == "NS.Shared.TestA")
            .ElementHits["FILE|Shared.cs|L10"].Should().Be(3);
        report.Entries.First(e => e.TestFullName == "NS.Shared.TestB")
            .ElementHits["FILE|Shared.cs|L10"].Should().Be(7);
    }

    // Test without document -> MissingCoverage (diagnostic, honest)
    [Fact]
    public void Map_TestWithoutDocument_MissingCoverage()
    {
        var records = new[] { Record("NS.Solo.Test") };
        var report = _mapper.Map(Array.Empty<CoverageDocument>(), records);

        report.Entries.Should().ContainSingle();
        report.Entries[0].Status.Should().Be(PerTestMappingStatus.MissingCoverage);
        report.Entries[0].Reason.Should().Contain("no coverage document");
        report.MissingCoverageCount.Should().Be(1);
    }

    // Document without TRX record -> Unmapped (honest, never fabricated)
    [Fact]
    public void Map_DocumentWithoutTest_UnmappedWithDiagnostic()
    {
        var doc = Document("cov-x.xml", "NS.Ghost", "Ghost.cs", (10, 2));

        var report = _mapper.Map(new[] { doc }, Array.Empty<TrxTestRecord>());

        report.Entries.Should().ContainSingle();
        report.Entries[0].Status.Should().Be(PerTestMappingStatus.Unmapped);
        report.Entries[0].TestIdentity.Should().BeNull();
        report.UnmappedDocumentCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("unmapped"));
    }

    // Empty TRX + empty documents -> empty report (no fabrication)
    [Fact]
    public void Map_EmptyInputs_EmptyReport()
    {
        var report = _mapper.Map(Array.Empty<CoverageDocument>(), Array.Empty<TrxTestRecord>());

        report.Entries.Should().BeEmpty();
        report.MappedCount.Should().Be(0);
        report.TotalDistinctElements.Should().Be(0);
    }

    // TotalDistinctElements — union across mapped entries
    [Fact]
    public void Map_TotalDistinctElements_UnionAcrossEntries()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs", (10, 3), (11, 1));
        var docB = Document("cov-B.xml", "NS.B", "B.cs", (10, 2));

        var report = _mapper.Map(new[] { docA, docB },
            new[] { Record("NS.A.T"), Record("NS.B.T") });

        // FILE|A.cs|L10, FILE|A.cs|L11, FILE|B.cs|L10 — 3 distinct
        report.TotalDistinctElements.Should().Be(3);
    }

    // Provenance — artifact path carried per entry
    [Fact]
    public void Map_Provenance_ArtifactPathCarried()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs", (10, 3));
        var report = _mapper.Map(new[] { docA }, new[] { Record("NS.A.T") });

        report.Entries[0].SourceArtifactPath.Should().Be("cov-A.xml");
    }

    // Mixed scenario (positional attribution v1): 2 records, 1 doc ->
    // doc[0]<->record[0] Mapped, record[1] MissingCoverage.
    // NOTE: Unmapped and Missing are MUTUALLY EXCLUSIVE under positional
    // attribution (docs>records -> Unmapped; records>docs -> Missing).
    // They can only coexist under name-based attribution (H-04.5/H-12).
    [Fact]
    public void Map_MoreRecordsThanDocs_MappedPlusMissing()
    {
        var docMapped = Document("cov-1.xml", "NS.M", "M.cs", (10, 3));
        var records = new[] { Record("NS.M.T"), Record("NS.Missing.T") };

        var report = _mapper.Map(new[] { docMapped }, records);

        report.MappedCount.Should().Be(1);
        report.MissingCoverageCount.Should().Be(1);
        report.UnmappedDocumentCount.Should().Be(0);
        report.Entries.Should().HaveCount(2);
    }

    // Mixed scenario: 2 docs, 1 record -> doc[0] Mapped, doc[1] Unmapped
    [Fact]
    public void Map_MoreDocsThanRecords_MappedPlusUnmapped()
    {
        var docMapped = Document("cov-1.xml", "NS.M", "M.cs", (10, 3));
        var docUnmapped = Document("cov-2.xml", "NS.Ghost", "G.cs", (10, 1));
        var records = new[] { Record("NS.M.T") };

        var report = _mapper.Map(new[] { docMapped, docUnmapped }, records);

        report.MappedCount.Should().Be(1);
        report.UnmappedDocumentCount.Should().Be(1);
        report.MissingCoverageCount.Should().Be(0);
        report.Entries.Should().HaveCount(2);
    }

    // Contract violations fail fast
    [Fact]
    public void Map_NullArguments_Throw()
    {
        Action nullDocs = () => _mapper.Map(null!, Array.Empty<TrxTestRecord>());
        Action nullRecords = () => _mapper.Map(Array.Empty<CoverageDocument>(), null!);

        nullDocs.Should().Throw<ArgumentNullException>();
        nullRecords.Should().Throw<ArgumentNullException>();
    }

    // CoveredElementCount — only hits>0 counted
    [Fact]
    public void Map_CoveredElementCount_OnlyPositiveHits()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs", (10, 3), (11, 0));
        var report = _mapper.Map(new[] { docA }, new[] { Record("NS.A.T") });

        report.Entries[0].CoveredElementCount.Should().Be(1);   // L10 only
    }

    // Determinism — same inputs, same output (inner sequences compared as
    // JOINED STRINGS — .Equal on List<string> compares by reference)
    [Fact]
    public void Map_Deterministic_SameInputSameOutput()
    {
        var docA = Document("cov-A.xml", "NS.A", "A.cs", (10, 3));
        var docB = Document("cov-B.xml", "NS.B", "B.cs", (10, 2));
        var records = new[] { Record("NS.A.T"), Record("NS.B.T") };

        var r1 = _mapper.Map(new[] { docA, docB }, records);
        var r2 = _mapper.Map(new[] { docA, docB }, records);

        r1.Entries.Select(e => e.TestFullName)
            .Should().Equal(r2.Entries.Select(e => e.TestFullName));

        r1.Entries.Select(e => string.Join("|", e.ElementHits.Keys.OrderBy(k => k)))
            .Should().Equal(r2.Entries.Select(e => string.Join("|", e.ElementHits.Keys.OrderBy(k => k))));

        r1.Entries.Select(e => string.Join("|", e.ElementHits.Values.OrderBy(v => v)))
            .Should().Equal(r2.Entries.Select(e => string.Join("|", e.ElementHits.Values.OrderBy(v => v))));
    }

    // Integration — real TRX record flows through (H-03.5 continuity)
    [Fact]
    public void Map_RealTrxRecord_FlowsThrough()
    {
        var trxPath = Path.Combine(Path.GetTempPath(), $"ptc-{Guid.NewGuid():N}.trx");
        File.WriteAllText(trxPath, """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <TestDefinitions>
    <UnitTest name="NS.MyClass.EventLogSizeCheck_Test" id="guid-1" storage="d:\out\ISCM.Tests.dll" />
  </TestDefinitions>
  <Results>
    <UnitTestResult executionId="guid-1" testName="EventLogSizeCheck_Test"
                    outcome="Failed" />
  </Results>
</TestRun>
""");
        var trxReport = new TrxIngestionService().Ingest(trxPath);

        var doc = Document("cov-1.xml", "NS.MyClass", "Calc.cs", (42, 3));
        var report = _mapper.Map(new[] { doc }, trxReport.Records.ToList());

        var entry = report.Entries[0];
        entry.TestFullName.Should().Be("NS.MyClass.EventLogSizeCheck_Test");
        entry.ElementHits.Should().ContainKey("FILE|Calc.cs|L42");

        try { File.Delete(trxPath); } catch { }
    }
}