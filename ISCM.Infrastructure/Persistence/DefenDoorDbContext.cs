using ISCM.Infrastructure.Persistence.Records;
using Microsoft.EntityFrameworkCore;

namespace ISCM.Infrastructure.Persistence;

/// <summary>
/// EF Core DbContext for DefenDoor persistence.
/// Phase 13.3: Initial schema for Snapshots, Findings, and EvidencePayloads.
/// </summary>
public class DefenDoorDbContext : DbContext
{
    public DefenDoorDbContext(DbContextOptions<DefenDoorDbContext> options) : base(options) { }

    public DbSet<SnapshotRecord> Snapshots => Set<SnapshotRecord>();
    public DbSet<FindingRecord> Findings => Set<FindingRecord>();
    public DbSet<EvidencePayloadRecord> EvidencePayloads => Set<EvidencePayloadRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply all IEntityTypeConfiguration<T> in this assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(DefenDoorDbContext).Assembly);
    }
}