using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CoverageProvenanceServiceTests
{
    private readonly CoverageProvenanceService _service = new();

    private static string WriteTempArtifact(string content)
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, content);
        return path;
    }

    private static CoverageDocument Document(string artifactPath) => new()
    {
        Status = CoverageParsingStatus.Parsed,
        SourceArtifactPath = artifactPath,
        TotalLines = 3,
        CoveredLines = 2
    };

    private static TrxIngestionReport Trx() => new()
    {
        Status = TrxIngestionStatus.Ingested,
        SourceArtifactPath = "d:/run/run.trx",
        Records = new[]
        {
            new TrxTestRecord { TestFullName = "NS.T1", Outcome = "Passed" },
            new TrxTestRecord { TestFullName = "NS.T2", Outcome = "Failed" }
        },
        UnknownDefinitionCount = 1
    };

    private static PerTestCoverageReport Mapping() => new()
    {
        Entries = new[]
        {
            new PerTestCoverage
            {
                Status = PerTestMappingStatus.Mapped,
                TestFullName = "NS.T1",
                SourceArtifactPath = "d:/cov/t1.xml",
                ElementHits = new Dictionary<string, int> { ["FILE|A.cs|L10"] = 1 }
            },
            new PerTestCoverage
            {
                Status = PerTestMappingStatus.Unmapped,
                SourceArtifactPath = "d:/cov/orphan.xml",
                Reason = "no matching TRX record"
            }
        },
        MappedCount = 1,
        UnmappedDocumentCount = 1,
        MissingCoverageCount = 0,
        TotalDistinctElements = 5
    };

    private static readonly ExecutionSessionId Session =
        ExecutionSessionId.Create("ES-0123456789abcdef0123456789abcdef");

    // 4.7.1 + 4.7.3 — EvidenceId is the content-hash prefix (formula-derived)
    [Fact]
    public void Build_EvidenceId_IsContentHashPrefix()
    {
        var artifact = WriteTempArtifact("coverage-bytes");
        try
        {
            var expectedHash = Convert.ToHexString(
                SHA256.HashData(File.ReadAllBytes(artifact)));

            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact)
            });

            record.Status.Should().Be(CoverageProvenanceStatus.Recorded);
            record.ArtifactSha256.Should().Be(expectedHash);
            record.EvidenceId.Should().NotBeNull();
            record.EvidenceId!.Value.Should().Be(
                $"EV-{expectedHash[..EvidenceId.HexLength]}");
            record.ArtifactSizeBytes.Should().BeGreaterThan(0);
        }
        finally { File.Delete(artifact); }
    }

    // determinism/replay — same bytes => same EvidenceId (no Guid, no clock)
    [Fact]
    public void Build_SameArtifactBytes_SameEvidenceId()
    {
        var artifact = WriteTempArtifact("deterministic-bytes");
        try
        {
            var first = _service.Build(new CoverageProvenanceInput { Document = Document(artifact) });
            var second = _service.Build(new CoverageProvenanceInput { Document = Document(artifact) });

            first.EvidenceId!.Value.Should().Be(second.EvidenceId!.Value);
            first.ArtifactSha256.Should().Be(second.ArtifactSha256);
        }
        finally { File.Delete(artifact); }
    }

    // different content => different identity
    [Fact]
    public void Build_DifferentContent_DifferentEvidenceId()
    {
        var a = WriteTempArtifact("content-A");
        var b = WriteTempArtifact("content-B");
        try
        {
            var ra = _service.Build(new CoverageProvenanceInput { Document = Document(a) });
            var rb = _service.Build(new CoverageProvenanceInput { Document = Document(b) });

            ra.EvidenceId!.Value.Should().NotBe(rb.EvidenceId!.Value);
        }
        finally { File.Delete(a); File.Delete(b); }
    }

    // canonical-contract compatibility — H-01.2 TryParse accepts the id
    [Fact]
    public void Build_EvidenceId_ValidatesAgainstCanonicalContract()
    {
        var artifact = WriteTempArtifact("canonical");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput { Document = Document(artifact) });

            EvidenceId.TryParse(record.EvidenceId!.Value, out var parsed)
                .Should().BeTrue();
            parsed!.Value.Should().Be(record.EvidenceId.Value);
        }
        finally { File.Delete(artifact); }
    }

    // 4.7.2 — collector name verbatim; version Unknown with diagnostic (never guessed)
    [Fact]
    public void Build_CollectorNameVerbatim_VersionUnknownWithDiagnostic()
    {
        var artifact = WriteTempArtifact("collector");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput { Document = Document(artifact) });

            record.CollectorName.Should().Be(CoverageCollectorService.AuthoritativeCollector);
            record.CollectorVersion.Should().BeNull();
            record.Diagnostics.Should().Contain(d => d.Contains("collector version Unknown"));
        }
        finally { File.Delete(artifact); }
    }

    // 4.7.4 — injected session carried; absent session = Unknown, never fabricated
    [Fact]
    public void Build_Session_InjectedCarried_AbsentUnknown()
    {
        var artifact = WriteTempArtifact("session");
        try
        {
            var withSession = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact),
                Session = Session
            });
            withSession.SessionId.Should().Be(Session);

            var withoutSession = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact)
            });
            withoutSession.SessionId.Should().BeNull();
        }
        finally { File.Delete(artifact); }
    }

    // KBF-06-009 — test-set identity + mapping completeness as first-class fields
    [Fact]
    public void Build_TestSetAndMappingCompleteness_CarriedAsFirstClassProvenance()
    {
        var artifact = WriteTempArtifact("completeness");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact),
                TestSet = Trx(),
                Mapping = Mapping(),
                Session = Session
            });

            record.HasTestSet.Should().BeTrue();
            record.TestSetStatus.Should().Be(TrxIngestionStatus.Ingested);
            record.TestSetArtifactPath.Should().Be("d:/run/run.trx");
            record.TestRecordCount.Should().Be(2);
            record.UnknownDefinitionCount.Should().Be(1);

            record.HasMappingCompleteness.Should().BeTrue();
            record.MappedCount.Should().Be(1);
            record.UnmappedDocumentCount.Should().Be(1);
            record.MissingCoverageCount.Should().Be(0);
            record.TotalDistinctElements.Should().Be(5);

            record.SchemaVersion.Should().Be(CoreSchema.CurrentVersion);
        }
        finally { File.Delete(artifact); }
    }

    // missing mapping completeness => explicit incompleteness diagnostic
    [Fact]
    public void Build_MappingNotProvided_IncompletenessIsExplicit()
    {
        var artifact = WriteTempArtifact("no-mapping");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact)
            });

            record.HasMappingCompleteness.Should().BeFalse();
            record.Diagnostics.Should().Contain(d =>
                d.Contains("mapping completeness not provided"));
        }
        finally { File.Delete(artifact); }
    }

    // 4.7.5 — parent artifact references: distinct, ORDINAL order.
    // Ordinal: uppercase 'C' (0x43) < lowercase 'd' (0x64), so the
    // Windows temp path (C:\...) sorts BEFORE the lowercase d:/ paths —
    // expectation derived from the actual ordinal formula (Dump lesson).
    [Fact]
    public void Build_ParentArtifactReferences_DistinctOrdinal()
    {
        var artifact = WriteTempArtifact("parents");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact),      // parent #1 (== collection artifact)
                Collection = new CoverageCollectionEvidence
                {
                    ArtifactPath = artifact          // duplicate on purpose
                },
                TestSet = Trx(),                     // parent #2
                Mapping = Mapping()                  // parents #3/#4
            });

            record.ParentArtifactPaths.Should().Equal(new[]
            {
                Path.GetFullPath(artifact),          // "C:\..." — uppercase sorts first (ordinal)
                "d:/cov/orphan.xml",
                "d:/cov/t1.xml",
                "d:/run/run.trx"
            });
        }
        finally { File.Delete(artifact); }
    }

    // explicit failure state — missing artifact: nothing fabricated
    [Fact]
    public void Build_ArtifactMissing_ExplicitState_NoFabricatedIdentity()
    {
        var record = _service.Build(new CoverageProvenanceInput
        {
            Document = Document("d:/nonexistent/coverage.cobertura.xml")
        });

        record.Status.Should().Be(CoverageProvenanceStatus.ArtifactMissing);
        record.EvidenceId.Should().BeNull();
        record.ArtifactSha256.Should().BeEmpty();
        record.ArtifactSizeBytes.Should().BeNull();
        record.Diagnostics.Should().Contain(d => d.Contains("not found on disk"));
    }

    // collection evidence carried (command audit copy, H-04.1.5)
    [Fact]
    public void Build_CollectionEvidence_ArgumentsCarried()
    {
        var artifact = WriteTempArtifact("collection");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = Document(artifact),
                Collection = new CoverageCollectionEvidence
                {
                    ArtifactPath = artifact,
                    Arguments = new[] { "test", "p.csproj", "--collect", "XPlat Code Coverage" }
                }
            });

            record.HasCollectionEvidence.Should().BeTrue();
            record.CollectorArguments.Should().Contain("XPlat Code Coverage");
        }
        finally { File.Delete(artifact); }
    }

    // corrupt artifact STILL gets an identity (hash of corrupt bytes — evidence preserved)
    [Fact]
    public void Build_CorruptArtifact_StillRecordedWithIdentity()
    {
        var artifact = WriteTempArtifact("<not-a-coverage-file>");
        try
        {
            var record = _service.Build(new CoverageProvenanceInput
            {
                Document = new CoverageDocument
                {
                    Status = CoverageParsingStatus.Corrupt,
                    SourceArtifactPath = artifact,
                    Reason = "unreadable XML"
                }
            });

            record.Status.Should().Be(CoverageProvenanceStatus.Recorded);
            record.EvidenceId.Should().NotBeNull();
        }
        finally { File.Delete(artifact); }
    }

    // H-01.8 — null inputs fail fast
    [Fact]
    public void Build_NullInputs_FailFast()
    {
        Action act1 = () => _service.Build(null!);
        Action act2 = () => _service.Build(new CoverageProvenanceInput { Document = null! });

        act1.Should().Throw<ArgumentNullException>();
        act2.Should().Throw<ArgumentNullException>();
    }
}