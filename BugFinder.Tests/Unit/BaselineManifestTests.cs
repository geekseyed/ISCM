using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class BaselineManifestTests
{
    private readonly BaselineManifestService _service = new();

    private const string AuditedHead = "86e0b257cc0d4c957f0120a1ea201ed8d3ebc067";
    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 5, 0, 0, TimeSpan.Zero);

    private static BaselineManifestInput SampleInput(
        string branch = "diagnostics-debug1/phase01-contract-repair",
        string sha = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111") => new()
        {
            RepositoryId = "geekseyed/ISCM",
            Branch = branch,
            CommitSha = sha,
            RecordedAtUtc = T0,
            AuditedHeadSha = AuditedHead,
            SolutionName = "ISCM.sln",
            TargetFramework = "net8.0",
            TestFramework = "xunit 2.7.0",
            TestSdkVersion = "17.9.0",
            BuildConfiguration = "Debug",
            TestCommand = "dotnet test BugFinder.Tests/ISCM.BugFinder.Tests.csproj",
            ResultArtifactPath = "TestResults/baseline.trx",
            PassedCount = 191,
            FailedCount = 0,
            SkippedCount = 0,
            ExecutionDuration = TimeSpan.FromSeconds(40)
        };

    // Stage 1.1.1-1.1.3 — all three sections populated
    [Fact]
    public void Build_PopulatesRepositoryExecutableAndExecutionSections()
    {
        var manifest = _service.Build(SampleInput());

        manifest.SchemaVersion.Should().Be(BaselineManifest.CurrentSchemaVersion);
        manifest.RepositoryId.Should().Be("geekseyed/ISCM");
        manifest.Branch.Should().Contain("phase01-contract-repair");
        manifest.CommitSha.Should().NotBeEmpty();
        manifest.AuditedHeadSha.Should().Be(AuditedHead);
        manifest.TargetFramework.Should().Be("net8.0");
        manifest.TestFramework.Should().Contain("xunit");
        manifest.PassedCount.Should().Be(191);
        manifest.FailedCount.Should().Be(0);
        manifest.ExecutionDuration.Should().BePositive();
    }

    // H-01.9.2 seed — serialization round trip preserves identity
    [Fact]
    public void SerializeDeserialize_RoundTrip_PreservesIdentity()
    {
        var manifest = _service.Build(SampleInput());

        var json = _service.Serialize(manifest);
        var restored = _service.Deserialize(json)!;

        restored.SchemaVersion.Should().Be(manifest.SchemaVersion);
        restored.Branch.Should().Be(manifest.Branch);
        restored.CommitSha.Should().Be(manifest.CommitSha);
        restored.AuditedHeadSha.Should().Be(manifest.AuditedHeadSha);
        restored.PassedCount.Should().Be(manifest.PassedCount);
        restored.ExecutionDuration.Should().Be(manifest.ExecutionDuration);
    }

    // H-01.1.4 — identical state passes the gate
    [Fact]
    public void Verify_IdenticalState_GatePassed()
    {
        var manifest = _service.Build(SampleInput());

        var report = _service.Verify(manifest,
            manifest.Branch, manifest.CommitSha, 191, 0, 0);

        report.Status.Should().Be(BaselineMatchStatus.Identical);
        report.StaleReferences.Should().BeEmpty();
        report.GatePassed.Should().BeTrue();
    }

    // H-01.1.4 — stale branch detected (the KBF-00-001 pattern)
    [Fact]
    public void Verify_StaleBranch_FailsGateWithFinding()
    {
        var manifest = _service.Build(SampleInput());

        var report = _service.Verify(manifest,
            "epic/phase16-advanced-reporting-analytics", manifest.CommitSha, 191, 0, 0);

        report.Status.Should().Be(BaselineMatchStatus.Different);
        report.GatePassed.Should().BeFalse();
        report.StaleReferences.Should().Contain(f =>
            f.Contains("stale branch reference")
            && f.Contains("epic/phase16"));
    }

    // H-01.1.4 — stale commit detected (the KBF-00-002 pattern)
    [Fact]
    public void Verify_StaleCommit_FailsGateWithFinding()
    {
        var manifest = _service.Build(SampleInput());

        var report = _service.Verify(manifest,
            manifest.Branch, "df03d37different", 191, 0, 0);

        report.GatePassed.Should().BeFalse();
        report.StaleReferences.Should().Contain(f => f.Contains("stale commit reference"));
    }

    // H-01.1.5 — count mismatch = non-reproducible execution
    [Fact]
    public void Verify_CountMismatch_ReportedAsNonReproducible()
    {
        var manifest = _service.Build(SampleInput());

        var report = _service.Verify(manifest,
            manifest.Branch, manifest.CommitSha, 190, 1, 0);

        report.GatePassed.Should().BeFalse();
        report.StaleReferences.Should().Contain(f =>
            f.Contains("non-reproducible test execution") && f.Contains("failed 1"));
    }

    // H-01.3 seed — incompatible schema version is Incomparable, not Different
    [Fact]
    public void Verify_SchemaVersionMismatch_Incomparable()
    {
        var original = _service.Build(SampleInput());
        var patched = _service.Deserialize(
            _service.Serialize(original).Replace(
                "\"SchemaVersion\": 1", "\"SchemaVersion\": 99"))!;
        var report = _service.Verify(patched,
            original.Branch, original.CommitSha, 191, 0, 0);

        report.Status.Should().Be(BaselineMatchStatus.Incomparable);
        report.GatePassed.Should().BeFalse();
        report.StaleReferences.Should().Contain(f => f.Contains("schema version mismatch"));
    }

    // Contract violations fail fast
    [Fact]
    public void Service_NullArguments_Throw()
    {
        Action nullBuild = () => _service.Build(null!);
        Action nullManifest = () => _service.Serialize(null!);
        Action nullVerify = () => _service.Verify(null!, "b", "s", 0, 0, 0);

        nullBuild.Should().Throw<ArgumentNullException>();
        nullManifest.Should().Throw<ArgumentNullException>();
        nullVerify.Should().Throw<ArgumentNullException>();
    }
}