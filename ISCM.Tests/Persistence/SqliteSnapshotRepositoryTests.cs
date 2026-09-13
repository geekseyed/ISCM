using FluentAssertions;
using ISCM.Application.Snapshots;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Persistence;
using ISCM.Infrastructure.Persistence.Mappers;
using ISCM.Infrastructure.Persistence.Repositories;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace ISCM.Tests.Persistence;

/// <summary>
/// Phase 13.8: Verifies SQLite persistence round-trip for snapshots.
/// Uses in-memory SQLite database for test isolation.
/// </summary>
public class SqliteSnapshotRepositoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DefenDoorDbContext _dbContext;
    private readonly SqliteSnapshotRepository _repository;

    public SqliteSnapshotRepositoryTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<DefenDoorDbContext>()
            .UseSqlite(_connection)
            .Options;

        _dbContext = new DefenDoorDbContext(options);
        _dbContext.Database.EnsureCreated();

        var mapper = new ScanResultToSnapshotMapper();
        _repository = new SqliteSnapshotRepository(_dbContext, mapper);
    }

    [Fact]
    public async Task SaveAsync_And_GetAsync_RoundTrip()
    {
        var snapshot = CreateTestSnapshot("HOST1");

        await _repository.SaveAsync(snapshot);
        var loaded = await _repository.GetAsync(snapshot.SnapshotId);

        loaded.Should().NotBeNull();
        loaded!.Hostname.Should().Be("HOST1");
        loaded.ComplianceScore.Should().Be(85);
        loaded.Findings.Should().HaveCount(2);
    }

    [Fact]
    public async Task SaveAsync_DuplicateScanId_ThrowsException()
    {
        var snapshot1 = CreateTestSnapshot("HOST1");
        var snapshot2 = new ScanSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            ScanId = snapshot1.ScanId, // Duplicate!
            Hostname = "HOST2",
            CompletedAtUtc = DateTime.UtcNow
        };

        await _repository.SaveAsync(snapshot1);

        var act = () => _repository.SaveAsync(snapshot2);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*ScanId*already exists*");
    }

    [Fact]
    public async Task GetByAssetAsync_ReturnsCorrectSnapshots()
    {
        var snap1 = CreateTestSnapshot("HOST1");
        var snap2 = CreateTestSnapshot("HOST1");
        var snap3 = CreateTestSnapshot("HOST2");

        await _repository.SaveAsync(snap1);
        await _repository.SaveAsync(snap2);
        await _repository.SaveAsync(snap3);

        var host1Snapshots = await _repository.GetByAssetAsync("HOST1");

        host1Snapshots.Should().HaveCount(2);
        host1Snapshots.Should().AllSatisfy(s => s.Hostname.Should().Be("HOST1"));
    }

    [Fact]
    public async Task DeleteAsync_RemovesSnapshotAndRelatedData()
    {
        var snapshot = CreateTestSnapshot("HOST1");
        await _repository.SaveAsync(snapshot);

        var deleted = await _repository.DeleteAsync(snapshot.SnapshotId);

        deleted.Should().BeTrue();
        var loaded = await _repository.GetAsync(snapshot.SnapshotId);
        loaded.Should().BeNull();

        var findings = await _dbContext.Findings.Where(f => f.SnapshotId == snapshot.SnapshotId).ToListAsync();
        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task ListSummariesAsync_ReturnsLightweightData()
    {
        var snapshot = CreateTestSnapshot("HOST1");
        await _repository.SaveAsync(snapshot);

        var summaries = await _repository.ListSummariesAsync();

        summaries.Should().HaveCount(1);
        summaries[0].Hostname.Should().Be("HOST1");
        summaries[0].ComplianceScore.Should().Be(85);
    }

    private ScanSnapshot CreateTestSnapshot(string hostname)
    {
        return new ScanSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            ScanId = Guid.NewGuid().ToString("N"),
            AssetId = hostname,
            Hostname = hostname,
            IpAddress = "192.168.1.1",
            MacAddress = "AA:BB:CC:DD:EE:FF",
            OsVersion = "10.0.22621",
            OsBuild = 22621,
            ScanMode = ScanMode.Full,
            ScannerVersion = "1.0.0",
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc = DateTime.UtcNow,
            OverallStatus = CheckStatus.Fail,
            ComplianceScore = 85,
            Grade = "B",
            PassCount = 17,
            FailCount = 3,
            WarningCount = 0,
            ErrorCount = 0,
            TotalControlCount = 10,
            TotalSubControlCount = 20,
            Findings = new List<FindingSnapshot>
            {
                new() { CheckId = "PWD-001", Name = "Password Policy", Status = CheckStatus.Pass, Severity = CheckSeverity.High, Category = CheckCategory.System },
                new() { CheckId = "LCK-001", Name = "Account Lockout", Status = CheckStatus.Fail, Severity = CheckSeverity.High, Category = CheckCategory.System }
            },
            Controls = new List<ControlSnapshot>(),
            IntegrityHash = "test-hash",
            SchemaVersion = 1
        };
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        _connection.Dispose();
    }
}