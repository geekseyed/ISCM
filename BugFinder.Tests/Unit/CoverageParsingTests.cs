using System;
using System.IO;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CoverageParsingTests : IDisposable
{
    private readonly CoverageParsingService _service = new();
    private readonly string _tempDirectory;

    public CoverageParsingTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"cpx-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private string WriteArtifact(string xml)
    {
        var path = Path.Combine(_tempDirectory, $"cov-{Guid.NewGuid():N}.cobertura.xml");
        File.WriteAllText(path, xml);
        return path;
    }

    // A realistic minimal cobertura document (coverlet XPlat shape)
    private const string CoberturaXml = """
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0.75" version="1.9">
  <modules>
    <module name="ISCM.Tests.dll" path="ISCM.Tests.dll">
      <classes>
        <class name="NS.MyClass" filename="Calc.cs" line-rate="0.75">
          <methods>
            <method name="Evaluate" signature="(System.Int32)" line-rate="1">
              <lines>
                <line number="10" hits="3" />
                <line number="11" hits="3" />
                <line number="12" hits="0" condition-coverage="50% (1/2)" />
              </lines>
            </method>
            <method name="Helper" signature="()" line-rate="0.5">
              <lines>
                <line number="20" hits="1" />
              </lines>
            </method>
          </methods>
          <lines>
            <line number="10" hits="3" />
            <line number="11" hits="3" />
            <line number="12" hits="0" />
            <line number="20" hits="1" />
          </lines>
        </class>
      </classes>
    </module>
  </modules>
</coverage>
""";

    // THE REAL COVERLET SHAPE — pinned from an actual coverage-evidence
    // artifact (H-04.8.2 inspection). Classes nest under packages/package,
    // NOT modules/module; class@name is fully qualified; @filename is a
    // repo-relative normalized path; lines carry branch/condition attrs.
    private const string RealCoverletXml = """
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0.5" branch-rate="0.5" version="1.9" timestamp="1791020861" lines-covered="1" lines-valid="2" branches-covered="0" branches-valid="0">
  <sources>
    <source>D:/Courses/C#-Project/ISCM/</source>
  </sources>
  <packages>
    <package name="ISCM.Application" line-rate="0.5" branch-rate="0.5" complexity="2">
      <classes>
        <class name="ISCM.Domain.ValueObjects.SnapshotExportPackage" filename="ISCM.Application/Snapshots/SnapshotExportPackage.cs" line-rate="0.5" branch-rate="1" complexity="2">
          <methods>
            <method name="get_ExportFormat" signature="()" line-rate="0" branch-rate="1" complexity="1">
              <lines>
                <line number="22" hits="0" branch="False" />
              </lines>
            </method>
            <method name="IsValid" signature="()" line-rate="1" branch-rate="1" complexity="1">
              <lines>
                <line number="60" hits="3" branch="False" />
              </lines>
            </method>
          </methods>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
""";

    // 4.2.1 — happy path parses everything
    [Fact]
    public void Parse_Cobertura_ParsesFullHierarchy()
    {
        var path = WriteArtifact(CoberturaXml);
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.Parsed);
        doc.TotalModules.Should().Be(1);
        doc.TotalClasses.Should().Be(1);
        doc.TotalMethods.Should().Be(2);
        doc.TotalLines.Should().Be(4);          // flattened deduped lines
        doc.CoveredLines.Should().Be(3);        // lines 10, 11, 20
        doc.LineRate.Should().Be(0.75m);
        doc.CollectorName.Should().Contain("XPlat Code Coverage");
    }

    // 4.2.5 — REAL per-line hits (the spectrum raw material)
    [Fact]
    public void Parse_PerLineHits_Preserved()
    {
        var path = WriteArtifact(CoberturaXml);
        var doc = _service.Parse(path);

        var lines = doc.Modules[0].Classes[0].AllLines;

        lines.First(l => l.LineNumber == 10).Hits.Should().Be(3);
        lines.First(l => l.LineNumber == 10).IsCovered.Should().BeTrue();
        lines.First(l => l.LineNumber == 12).Hits.Should().Be(0);
        lines.First(l => l.LineNumber == 12).IsCovered.Should().BeFalse();   // instrumented, not hit
        lines.First(l => l.LineNumber == 12).ConditionCoverage.Should().Contain("50%");
    }

    // 4.8.2 REGRESSION — the REAL coverlet shape parses (root-caused fix:
    // parser previously returned NoModules on every real artifact)
    [Fact]
    public void Parse_RealCoverletPackageShape_ParsesHierarchy()
    {
        var path = WriteArtifact(RealCoverletXml);
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.Parsed);
        doc.TotalModules.Should().Be(1);
        doc.TotalClasses.Should().Be(1);
        doc.TotalMethods.Should().Be(2);

        var cls = doc.Modules.Single().Classes.Single();
        cls.ClassName.Should().Be("ISCM.Domain.ValueObjects.SnapshotExportPackage");
        cls.SourceFilePath.Should().Be("ISCM.Application/Snapshots/SnapshotExportPackage.cs");
        doc.TotalLines.Should().Be(2);
        doc.CoveredLines.Should().Be(1);
    }

    // 4.8.2 REGRESSION — real-shape per-line hits preserved (0 and >0)
    [Fact]
    public void Parse_RealCoverletPackageShape_PerLineHitsPreserved()
    {
        var path = WriteArtifact(RealCoverletXml);
        var doc = _service.Parse(path);

        var lines = doc.Modules[0].Classes[0].AllLines;
        lines.First(l => l.LineNumber == 22).Hits.Should().Be(0);
        lines.First(l => l.LineNumber == 22).IsCovered.Should().BeFalse();
        lines.First(l => l.LineNumber == 60).Hits.Should().Be(3);
        lines.First(l => l.LineNumber == 60).IsCovered.Should().BeTrue();
    }

    // 4.8.2 REGRESSION — NEITHER container => explicit NoModules (unchanged)
    [Fact]
    public void Parse_NoContainers_NoModules()
    {
        var path = WriteArtifact(
            "<?xml version=\"1.0\"?><coverage line-rate=\"1\"><sources><source>D:/r/</source></sources></coverage>");
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.NoModules);
        doc.Reason.Should().Contain("module/package");
    }

    // 4.2.3/4.2.4 — hierarchy: module -> class -> methods
    // (methods ordered by Signature ordinal per the service contract)
    [Fact]
    public void Parse_Hierarchy_ModuleClassMethod()
    {
        var path = WriteArtifact(CoberturaXml);
        var doc = _service.Parse(path);

        var module = doc.Modules.Single();
        module.ModuleName.Should().Be("ISCM.Tests.dll");

        var cls = module.Classes.Single();
        cls.ClassName.Should().Be("NS.MyClass");
        cls.SourceFilePath.Should().Be("Calc.cs");   // normalized (no backslash change needed)

        // deterministic ordering: by Signature ordinal — "()" < "(System.Int32)"
        cls.Methods.Select(m => m.MethodName).Should().ContainInOrder("Helper", "Evaluate");
        cls.Methods.First(m => m.MethodName == "Evaluate").Signature.Should().Be("(System.Int32)");
        cls.Methods.First(m => m.MethodName == "Helper").Signature.Should().Be("()");
    }

    // 4.2.6 — source artifact identity carried
    [Fact]
    public void Parse_SourceArtifactPath_Carried()
    {
        var path = WriteArtifact(CoberturaXml);
        var doc = _service.Parse(path);

        doc.SourceArtifactPath.Should().Be(path);
    }

    // 4.2.1 — missing file explicit
    [Fact]
    public void Parse_MissingFile_FileMissing()
    {
        var doc = _service.Parse(Path.Combine(_tempDirectory, "missing.cobertura.xml"));

        doc.Status.Should().Be(CoverageParsingStatus.FileMissing);
        doc.Reason.Should().Contain("not found");
        doc.Modules.Should().BeEmpty();
    }

    // 4.2.1 — corrupt XML explicit with reason
    [Fact]
    public void Parse_CorruptXml_CorruptWithReason()
    {
        var path = WriteArtifact("<<< not xml >>>");
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.Corrupt);
        doc.Reason.Should().NotBeNullOrWhiteSpace();
        doc.Modules.Should().BeEmpty();
    }

    // KBF-06-002 — wrong root = UnsupportedFormat (explicit detection, not guess)
    [Fact]
    public void Parse_WrongRoot_UnsupportedFormat()
    {
        var path = WriteArtifact("<?xml version=\"1.0\"?><not-coverage />");
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.UnsupportedFormat);
        doc.Reason.Should().Contain("expected 'coverage'");
    }

    // cobertura without line-rate = not a real cobertura doc
    [Fact]
    public void Parse_MissingLineRate_UnsupportedFormat()
    {
        var path = WriteArtifact("<?xml version=\"1.0\"?><coverage />");
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.UnsupportedFormat);
        doc.Reason.Should().Contain("line-rate");
    }

    // Explicit NoModules (never fabricated empty success)
    [Fact]
    public void Parse_NoModules_ExplicitStatus()
    {
        var path = WriteArtifact(
            "<?xml version=\"1.0\"?><coverage line-rate=\"0\"><modules /></coverage>");
        var doc = _service.Parse(path);

        doc.Status.Should().Be(CoverageParsingStatus.NoModules);
        doc.Reason.Should().Contain("zero module");
    }

    // Lines deduped across methods (same line in two methods = one entry, max hits)
    [Fact]
    public void Parse_DuplicateLinesAcrossMethods_DedupedWithMaxHits()
    {
        var xml = """
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="1">
  <modules>
    <module name="M.dll">
      <classes>
        <class name="C" filename="C.cs" line-rate="1">
          <methods>
            <method name="M1" signature="()" line-rate="1">
              <lines><line number="5" hits="2" /></lines>
            </method>
            <method name="M2" signature="()" line-rate="1">
              <lines><line number="5" hits="4" /></lines>
            </method>
          </methods>
        </class>
      </classes>
    </module>
  </modules>
</coverage>
""";
        var path = WriteArtifact(xml);
        var doc = _service.Parse(path);

        var lines = doc.Modules[0].Classes[0].AllLines;
        lines.Should().ContainSingle();
        lines[0].LineNumber.Should().Be(5);
        lines[0].Hits.Should().Be(4);   // max across methods
    }

    // Empty path / missing file fail fast
    [Fact]
    public void Parse_EmptyPath_Throws()
    {
        Action act = () => _service.Parse("  ");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Parse_NullPath_Throws()
    {
        Action act = () => _service.Parse(null!);
        act.Should().Throw<ArgumentException>();
    }

    // Provenance — collector name carried on the document (H-04.7 seed)
    [Fact]
    public void Parse_CollectorProvenance_Carried()
    {
        var path = WriteArtifact(CoberturaXml);
        var doc = _service.Parse(path);

        doc.CollectorName.Should().Be(CoverageCollectorService.AuthoritativeCollector);
    }
}