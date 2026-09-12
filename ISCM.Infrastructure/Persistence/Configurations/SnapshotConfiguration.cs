using ISCM.Infrastructure.Persistence.Records;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ISCM.Infrastructure.Persistence.Configurations;

public class SnapshotConfiguration : IEntityTypeConfiguration<SnapshotRecord>
{
    public void Configure(EntityTypeBuilder<SnapshotRecord> builder)
    {
        builder.ToTable("Snapshots");
        builder.HasKey(s => s.Id);

        // Indexes for fast lookups
        builder.HasIndex(s => s.ScanId).IsUnique();
        builder.HasIndex(s => s.AssetId);
        builder.HasIndex(s => s.Hostname);
        builder.HasIndex(s => s.CompletedAtUtc);

        builder.Property(s => s.ScanId).IsRequired().HasMaxLength(64);
        builder.Property(s => s.AssetId).IsRequired().HasMaxLength(256);
        builder.Property(s => s.Hostname).IsRequired().HasMaxLength(256);
        builder.Property(s => s.IpAddress).HasMaxLength(64);
        builder.Property(s => s.MacAddress).HasMaxLength(64);
        builder.Property(s => s.OsVersion).HasMaxLength(128);
        builder.Property(s => s.ScanMode).HasMaxLength(32);
        builder.Property(s => s.BaselineId).HasMaxLength(128);
        builder.Property(s => s.BaselineName).HasMaxLength(256);
        builder.Property(s => s.ScannerVersion).HasMaxLength(32);
        builder.Property(s => s.OverallStatus).HasMaxLength(32);
        builder.Property(s => s.Grade).HasMaxLength(8);
        builder.Property(s => s.IntegrityHash).HasMaxLength(128);
    }
}