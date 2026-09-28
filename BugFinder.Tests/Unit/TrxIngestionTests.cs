using System;
using System.IO;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class TrxIngestionTests : IDisposable
{
    private readonly TrxIngestionService _service = new();
    private readonly string _tempDirectory;

    public TrxIngestionTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"trx-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private string WriteTrx(string xml)
    {
        var path = Path.Combine(_tempDirectory, $"probe-{Guid.NewGuid():N}.trx");
        File.WriteAllText(path, xml);
        return path;
    }

    private const string RealTrx = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Times start="2026-09-27T12:00:00.000Z" finish="2026-09-27T12:00:30.000Z" />
  <TestDefinitions>
    <UnitTest name="NS.MyClass.EventLogSizeCheck_Test" id="guid-1" storage="d:\out\ISCM.Tests.dll">
      <TestMethod className="NS.MyClass" name="EventLogSizeCheck_Test" codeBase="d:\out\ISCM.Tests.dll" />
    </UnitTest>
    <UnitTest name="NS.MyClass.AdminCount_Test" id="guid-2" storage="d:\out\ISCM.Tests.dll">
      <TestMethod className="NS.MyClass" name="AdminCount_Test" codeBase="d:\out\ISCM.Tests.dll" />
    </UnitTest>
  </TestDefinitions>
  <Results>
    <UnitTestResult executionId="guid-1" testName="EventLogSizeCheck_Test"
                    outcome="Failed" startTime="2026-09-27T12:00:05.000Z"
                    endTime="2026-09-27T12:00:07.500Z" duration="00:00:02.500" />
    <UnitTestResult executionId="guid-2" testName="AdminCount_Test"
                    outcome="Passed" startTime="2026-09-27T12:00:08.000Z"
                    endTime="2026-09-27T12:00:09.000Z" duration="00:00:01.000" />
  </Results>
</TestRun>
""";

    // 3.5.2 — REAL assembly identity from storage (never hard-coded)
    [Fact]
    public void Ingest_AssemblyIdentity_FromStorage()
    {
        var path = WriteTrx(RealTrx);
        var report = _service.Ingest(path);

        report.Status.Should().Be(TrxIngestionStatus.Ingested);
        report.Records.Should().HaveCount(2);
        report.Records.Should().OnlyContain(r => r.AssemblyPath == "d:/out/ISCM.Tests.dll");
    }

    // 3.5.3-3.5.6 — real timestamps from XML (not UtcNow)
    [Fact]
    public void Ingest_Timestamps_RealFromXml()
    {
        var path = WriteTrx(RealTrx);
        var report = _service.Ingest(path);

        var failed = report.Records.First(r => r.Outcome == "Failed");
        failed.StartedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:05.000Z"));
        failed.CompletedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:07.500Z"));
        failed.Duration.Should().Be(TimeSpan.FromSeconds(2.5));

        report.RunStartedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:00.000Z"));
        report.RunFinishedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:30.000Z"));
    }

    // 3.5.7 — unknown definition PRESERVED (KBF-01-005)
    [Fact]
    public void Ingest_UnknownDefinition_PreservedNotSkipped()
    {
        var xml = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <TestDefinitions>
    <UnitTest name="NS.Known.Test" id="guid-known" storage="d:\out\Known.dll" />
  </TestDefinitions>
  <Results>
    <UnitTestResult executionId="guid-known" testName="NS.Known.Test"
                    outcome="Passed" />
    <UnitTestResult executionId="guid-UNKNOWN" testName="NS.Ghost.Test"
                    outcome="Failed" />
  </Results>
</TestRun>
""";
        var path = WriteTrx(xml);
        var report = _service.Ingest(path);

        report.Status.Should().Be(TrxIngestionStatus.Ingested);
        report.Records.Should().HaveCount(2);               // both preserved!
        report.UnknownDefinitionCount.Should().Be(1);
        report.Diagnostics.Should().Contain(d => d.Contains("guid-UNKNOWN"));

        var ghost = report.Records.First(r => r.IsUnknownDefinition);
        ghost.TestFullName.Should().Be("NS.Ghost.Test");    // fallback to result name
        ghost.AssemblyPath.Should().BeEmpty();               // unknown = empty (H-01.4)
    }

    // KBF-01-006 — no hard-coded assembly name
    [Fact]
    public void Ingest_NonDefaultAssemblyName_ReflectsRealIdentity()
    {
        var xml = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <TestDefinitions>
    <UnitTest name="Other.Project.Tests.Custom_Test" id="guid-x" storage="d:\other\Other.Project.Tests.dll" />
  </TestDefinitions>
  <Results>
    <UnitTestResult executionId="guid-x" testName="Custom_Test" outcome="Passed" />
  </Results>
</TestRun>
""";
        var path = WriteTrx(xml);
        var report = _service.Ingest(path);

        report.Records[0].AssemblyPath.Should().Be("d:/other/Other.Project.Tests.dll");
        report.Records[0].AssemblyPath.Should().NotContain("ISCM.Tests");  // never fabricated
    }

    // 3.5.3-3.5.6 — missing timestamps = null (X-004: not zero)
    [Fact]
    public void Ingest_MissingTimestamps_NullNotZero()
    {
        var xml = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Results>
    <UnitTestResult executionId="guid-1" testName="T1" outcome="Passed" />
  </Results>
</TestRun>
""";
        var path = WriteTrx(xml);
        var report = _service.Ingest(path);

        var record = report.Records.Single();
        record.StartedUtc.Should().BeNull();
        record.CompletedUtc.Should().BeNull();
        record.Duration.Should().BeNull();
    }

    // Missing file — explicit, not empty
    [Fact]
    public void Ingest_MissingFile_ExplicitStatus()
    {
        var report = _service.Ingest(
            Path.Combine(_tempDirectory, "missing.trx"));

        report.Status.Should().Be(TrxIngestionStatus.FileMissing);
        report.Records.Should().BeEmpty();
        report.Reason.Should().Contain("not found");
    }

    // Corrupt XML — explicit + reason (anti-KBF-11-004)
    [Fact]
    public void Ingest_CorruptXml_ExplicitStatusWithReason()
    {
        var path = WriteTrx("<this is not xml <<<");
        var report = _service.Ingest(path);

        report.Status.Should().Be(TrxIngestionStatus.Corrupt);
        report.Reason.Should().NotBeNullOrWhiteSpace();
        report.Records.Should().BeEmpty();
    }

    // Wrong root element — corrupt
    [Fact]
    public void Ingest_WrongRoot_Corrupt()
    {
        var path = WriteTrx("<NotATestRun><Something/></NotATestRun>");
        var report = _service.Ingest(path);

        report.Status.Should().Be(TrxIngestionStatus.Corrupt);
        report.Reason.Should().Contain("TestRun");
    }

    // No results — explicit (never fabricated as success)
    [Fact]
    public void Ingest_ZeroResults_ExplicitNoResults()
    {
        var xml = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <TestDefinitions />
  <Results />
</TestRun>
""";
        var path = WriteTrx(xml);
        var report = _service.Ingest(path);

        report.Status.Should().Be(TrxIngestionStatus.NoResults);
        report.Records.Should().BeEmpty();
        report.Reason.Should().Contain("zero UnitTestResult");
    }

    // Deterministic ordering by completion time
    [Fact]
    public void Ingest_Ordering_DeterministicByCompletionTime()
    {
        var path = WriteTrx(RealTrx);
        var report = _service.Ingest(path);

        report.Records.Select(r => r.CompletedUtc)
            .Should().BeInAscendingOrder();
    }

    // Contract violations fail fast
    [Fact]
    public void Ingest_EmptyPath_Throws()
    {
        Action act = () => _service.Ingest("  ");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Ingest_NullPath_Throws()
    {
        Action act = () => _service.Ingest(null!);
        act.Should().Throw<ArgumentException>();
    }
}