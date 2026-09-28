using System;
using System.IO;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;

namespace ISCM.Tests.Unit.BugFinder;

public class DomainResultIngestionTests : IDisposable
{
    private readonly DomainResultIngestionService _service = new();
    private readonly string _tempDirectory;

    public DomainResultIngestionTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"dom-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private string WriteJson(string json)
    {
        var path = Path.Combine(_tempDirectory, $"dom-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return path;
    }

    private const string FullRecordJson = """
[
  {
    "subControlId": "EVL-001.4",
    "status": "Fail",
    "reason": "expected 512 MB, actual 128 MB",
    "expected": "512",
    "actual": "128",
    "sourceTestId": "EventLogSizeCheck_Test"
  }
]
""";

    // KBF-01-008 — ALL SIX fields parsed (the fix)
    [Fact]
    public void Ingest_AllSixFields_Parsed()
    {
        var report = _service.IngestFromJson(FullRecordJson);

        report.Status.Should().Be(DomainResultIngestionStatus.Ingested);
        report.Records.Should().ContainSingle();

        var record = report.Records[0];
        record.SubControlId.Should().Be("EVL-001.4");
        record.Status.Should().Be(CheckStatus.Fail);
        record.Reason.Should().Be("expected 512 MB, actual 128 MB");
        record.Expected.Should().Be("512");           // KBF-01-008 fix
        record.Actual.Should().Be("128");             // KBF-01-008 fix
        record.SourceTestId.Should().Be("EventLogSizeCheck_Test"); // KBF-01-008 fix
    }

    // Status case-insensitive
    [Theory]
    [InlineData("fail", CheckStatus.Fail)]
    [InlineData("FAIL", CheckStatus.Fail)]
    [InlineData("Pass", CheckStatus.Pass)]
    [InlineData("Error", CheckStatus.Error)]
    [InlineData("Disagreement", CheckStatus.Disagreement)]
    [InlineData("NotApplicable", CheckStatus.NotApplicable)]
    public void Ingest_Status_CaseInsensitive(string raw, CheckStatus expected)
    {
        var report = _service.IngestFromJson(
            $$"""[ { "subControlId": "E1", "status": "{{raw}}" } ]""");

        report.Records[0].Status.Should().Be(expected);
        report.Records[0].RawStatus.Should().Be(raw);
    }

    // H-01.4 — unparseable status -> Unknown + raw preserved + diagnostic
    [Fact]
    public void Ingest_UnparseableStatus_UnknownWithDiagnostic()
    {
        var report = _service.IngestFromJson(
            """[ { "subControlId": "E1", "status": "Banana" } ]""");

        var record = report.Records.Single();
        record.Status.Should().Be(CheckStatus.Unknown);
        record.RawStatus.Should().Be("Banana");
        report.UnparseableStatusCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("Banana"));
    }

    [Fact]
    public void Ingest_MissingStatus_UnknownWithDiagnostic()
    {
        var report = _service.IngestFromJson("""[ { "subControlId": "E1" } ]""");

        report.Records[0].Status.Should().Be(CheckStatus.Unknown);
        report.UnparseableStatusCount.Should().Be(1);
    }

    // 3.6.2 — missing subControlId: recorded with empty id + diagnostic
    [Fact]
    public void Ingest_MissingSubControlId_RecordedWithDiagnostic()
    {
        var report = _service.IngestFromJson("""[ { "status": "Fail" } ]""");

        report.Records.Should().ContainSingle();
        report.Records[0].SubControlId.Should().BeEmpty();
        report.MissingSubControlIdCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("subControlId"));
    }

    // 3.6.8 — malformed element skipped + counted + diagnosed
    [Fact]
    public void Ingest_MalformedElements_SkippedCountedDiagnosed()
    {
        var report = _service.IngestFromJson(
            """[ { "subControlId": "E1", "status": "Fail" }, "not-an-object", 42 ]""");

        report.Records.Should().ContainSingle();
        report.SkippedMalformedCount.Should().Be(2);
        report.Diagnostics.Should().Contain(d => d.Contains("malformed record"));
    }

    // X-002 — corrupt JSON explicit (never empty success)
    [Fact]
    public void Ingest_CorruptJson_ExplicitWithReason()
    {
        var report = _service.IngestFromJson("{ not json <<<");

        report.Status.Should().Be(DomainResultIngestionStatus.Corrupt);
        report.Records.Should().BeEmpty();
        report.Reason.Should().Contain("unreadable");
    }

    // Not an array — corrupt
    [Fact]
    public void Ingest_NonArrayRoot_Corrupt()
    {
        var report = _service.IngestFromJson("""{ "subControlId": "E1" }""");

        report.Status.Should().Be(DomainResultIngestionStatus.Corrupt);
        report.Reason.Should().Contain("JSON array");
    }

    // Empty array — explicit NoRecords (never fabricated success)
    [Fact]
    public void Ingest_EmptyArray_ExplicitNoRecords()
    {
        var report = _service.IngestFromJson("[]");

        report.Status.Should().Be(DomainResultIngestionStatus.NoRecords);
        report.Records.Should().BeEmpty();
        report.Reason.Should().Contain("empty");
    }

    // File shape — missing/corrupt via file path
    [Fact]
    public void IngestFromFile_MissingFile_Explicit()
    {
        var report = _service.IngestFromFile(
            Path.Combine(_tempDirectory, "missing.json"));

        report.Status.Should().Be(DomainResultIngestionStatus.FileMissing);
        report.Reason.Should().Contain("not found");
    }

    [Fact]
    public void IngestFromFile_CorruptFile_Explicit()
    {
        var path = WriteJson("<not json>");
        var report = _service.IngestFromFile(path);

        report.Status.Should().Be(DomainResultIngestionStatus.Corrupt);
        report.SourceArtifactPath.Should().Be(path);
    }

    // IngestFromFile happy path
    [Fact]
    public void IngestFromFile_HappyPath_ParsesAllFields()
    {
        var path = WriteJson(FullRecordJson);
        var report = _service.IngestFromFile(path);

        report.Status.Should().Be(DomainResultIngestionStatus.Ingested);
        report.SourceArtifactPath.Should().Be(path);
        report.Records[0].ToNormalizedEvaluationResult().SubControlId.Should().Be("EVL-001.4");
    }

    // H-02.1 adoption bridge — projection produces the BF-01 shape
    [Fact]
    public void Projection_ToNormalizedEvaluationResult_AllFieldsCarried()
    {
        var report = _service.IngestFromJson(FullRecordJson);
        var normalized = report.Records[0].ToNormalizedEvaluationResult();

        normalized.SubControlId.Should().Be("EVL-001.4");
        normalized.Status.Should().Be(CheckStatus.Fail);
        normalized.Reason.Should().Be("expected 512 MB, actual 128 MB");
        normalized.Expected.Should().Be("512");
        normalized.Actual.Should().Be("128");
        normalized.SourceTestId.Should().Be("EventLogSizeCheck_Test");
    }

    // Deterministic ordering: SubControlId then SourceTestId
    [Fact]
    public void Ingest_Ordering_Deterministic()
    {
        var report = _service.IngestFromJson("""
[
  { "subControlId": "EVL-002", "status": "Pass" },
  { "subControlId": "EVL-001", "status": "Fail", "sourceTestId": "B" },
  { "subControlId": "EVL-001", "status": "Pass", "sourceTestId": "A" }
]
""");

        report.Records.Select(r => (r.SubControlId, r.SourceTestId))
            .Should().ContainInOrder(
                ("EVL-001", "A"), ("EVL-001", "B"), ("EVL-002", null));
    }

    // Case-insensitive property names (documented convenience)
    [Fact]
    public void Ingest_PropertyNames_CaseInsensitive()
    {
        var report = _service.IngestFromJson(
            """[ { "SUBCONTROLID": "E1", "STATUS": "Fail" } ]""");

        report.Records[0].SubControlId.Should().Be("E1");
        report.Records[0].Status.Should().Be(CheckStatus.Fail);
    }

    // Contract violations fail fast
    [Fact]
    public void Ingest_EmptyJson_Throws()
    {
        Action act = () => _service.IngestFromJson("  ");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IngestFromFile_EmptyPath_Throws()
    {
        Action act = () => _service.IngestFromFile(" ");
        act.Should().Throw<ArgumentException>();
    }
}