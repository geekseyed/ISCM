using FluentAssertions;
using ISCM.Application.Snapshots;
using ISCM.Domain.Enums;
using Xunit;

namespace ISCM.Tests.Snapshots;

/// <summary>
/// Phase 13.8: Verifies semantic comparison of ScanSnapshots.
/// </summary>
public class SnapshotDiffEngineTests
{
    private readonly SnapshotDiffEngine _engine = new();

    [Fact]
    public void Compare_IdenticalSnapshots_ReturnsIdentical()
    {
        var snapshot = CreateTestSnapshot("HOST1", 80, new[] { ("PWD-001.1", CheckStatus.Pass) });

        var result = _engine.Compare(snapshot, snapshot);

        result.OverallVerdict.Should().Be(DiffVerdict.Identical);
        result.Summary.TotalChanges.Should().Be(0);
        _engine.AreEquivalent(snapshot, snapshot).Should().BeTrue();
    }

    [Fact]
    public void Compare_Improvement_ReturnsImproved()
    {
        var before = CreateTestSnapshot("HOST1", 50, new[] { ("PWD-001.1", CheckStatus.Fail) });
        var after = CreateTestSnapshot("HOST1", 100, new[] { ("PWD-001.1", CheckStatus.Pass) });

        var result = _engine.Compare(before, after);

        result.OverallVerdict.Should().Be(DiffVerdict.Improved);
        result.Summary.Improved.Should().Be(1);
        result.Summary.Regressed.Should().Be(0);
        _engine.HasImprovements(before, after).Should().BeTrue();
        _engine.HasRegressions(before, after).Should().BeFalse();
    }

    [Fact]
    public void Compare_Regression_ReturnsRegressed()
    {
        var before = CreateTestSnapshot("HOST1", 100, new[] { ("PWD-001.1", CheckStatus.Pass) });
        var after = CreateTestSnapshot("HOST1", 50, new[] { ("PWD-001.1", CheckStatus.Fail) });

        var result = _engine.Compare(before, after);

        result.OverallVerdict.Should().Be(DiffVerdict.Regressed);
        result.Summary.Regressed.Should().Be(1);
        result.Summary.Improved.Should().Be(0);
        _engine.HasRegressions(before, after).Should().BeTrue();
    }

    [Fact]
    public void Compare_MixedChanges_ReturnsMixed()
    {
        var before = CreateTestSnapshot("HOST1", 50, new[]
        {
            ("PWD-001.1", CheckStatus.Fail),
            ("LCK-001.1", CheckStatus.Pass)
        });
        var after = CreateTestSnapshot("HOST1", 50, new[]
        {
            ("PWD-001.1", CheckStatus.Pass),   // Improved
            ("LCK-001.1", CheckStatus.Fail)    // Regressed
        });

        var result = _engine.Compare(before, after);

        result.OverallVerdict.Should().Be(DiffVerdict.Mixed);
        result.Summary.Improved.Should().Be(1);
        result.Summary.Regressed.Should().Be(1);
    }

    [Fact]
    public void Compare_AddedSubControl_ReturnsBaselineChanged()
    {
        var before = CreateTestSnapshot("HOST1", 100, new[] { ("PWD-001.1", CheckStatus.Pass) });
        var after = CreateTestSnapshot("HOST1", 100, new[]
        {
            ("PWD-001.1", CheckStatus.Pass),
            ("LCK-001.1", CheckStatus.Pass)  // Added
        });

        var result = _engine.Compare(before, after);

        result.Summary.Added.Should().Be(1);
        result.SubControlChanges.Should().Contain(c =>
            c.SubControlId == "LCK-001.1" && c.ChangeType == ChangeType.Added);
    }

    [Fact]
    public void Compare_RemovedSubControl_ReturnsRemoved()
    {
        var before = CreateTestSnapshot("HOST1", 100, new[]
        {
            ("PWD-001.1", CheckStatus.Pass),
            ("LCK-001.1", CheckStatus.Pass)
        });
        var after = CreateTestSnapshot("HOST1", 100, new[] { ("PWD-001.1", CheckStatus.Pass) });

        var result = _engine.Compare(before, after);

        result.Summary.Removed.Should().Be(1);
        result.SubControlChanges.Should().Contain(c =>
            c.SubControlId == "LCK-001.1" && c.ChangeType == ChangeType.Removed);
    }

    [Fact]
    public void Compare_ComplianceScoreDelta_IsCorrect()
    {
        var before = CreateTestSnapshot("HOST1", 70, new[] { ("PWD-001.1", CheckStatus.Fail) });
        var after = CreateTestSnapshot("HOST1", 90, new[] { ("PWD-001.1", CheckStatus.Pass) });

        var result = _engine.Compare(before, after);

        result.ComplianceScoreDelta.Should().Be(20);
    }

    private ScanSnapshot CreateTestSnapshot(string hostname, int score, (string id, CheckStatus status)[] subControls)
    {
        var findings = subControls.Select(sc => new FindingSnapshot
        {
            CheckId = sc.id.Split('.')[0],
            SubControlId = sc.id,
            Name = $"Test {sc.id}",
            Status = sc.status,
            Severity = CheckSeverity.Medium,
            Category = CheckCategory.System
        }).ToList();

        var controls = subControls
            .GroupBy(sc => sc.id.Split('.')[0])
            .Select(g => new ControlSnapshot
            {
                ControlId = g.Key,
                Status = g.Any(sc => sc.status == CheckStatus.Fail) ? CheckStatus.Fail : CheckStatus.Pass,
                SubControls = g.Select(sc => new SubControlSnapshot
                {
                    SubControlId = sc.id,
                    Status = sc.status,
                    EvaluatedAt = DateTime.UtcNow
                }).ToList()
            }).ToList();

        return new ScanSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            ScanId = Guid.NewGuid().ToString("N"),
            AssetId = hostname,
            Hostname = hostname,
            CompletedAtUtc = DateTime.UtcNow,
            ComplianceScore = score,
            PassCount = subControls.Count(sc => sc.status == CheckStatus.Pass),
            FailCount = subControls.Count(sc => sc.status == CheckStatus.Fail),
            Findings = findings,
            Controls = controls
        };
    }
}