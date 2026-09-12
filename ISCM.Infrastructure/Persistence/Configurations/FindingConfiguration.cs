using ISCM.Infrastructure.Persistence.Records;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ISCM.Infrastructure.Persistence.Configurations;

public class FindingConfiguration : IEntityTypeConfiguration<FindingRecord>
{
    public void Configure(EntityTypeBuilder<FindingRecord> builder)
    {
        builder.ToTable("Findings");
        builder.HasKey(f => f.Id);

        builder.HasIndex(f => f.SnapshotId);
        builder.HasIndex(f => f.CheckId);
        builder.HasIndex(f => new { f.CheckId, f.SubControlId });
        builder.HasIndex(f => f.Status);
        builder.HasIndex(f => f.Severity);

        builder.Property(f => f.CheckId).IsRequired().HasMaxLength(64);
        builder.Property(f => f.SubControlId).HasMaxLength(64);
        builder.Property(f => f.Name).IsRequired().HasMaxLength(512);
        builder.Property(f => f.Category).HasMaxLength(64);
        builder.Property(f => f.Severity).HasMaxLength(32);
        builder.Property(f => f.Status).HasMaxLength(32);
        builder.Property(f => f.CurrentValue).HasMaxLength(1024);
        builder.Property(f => f.ExpectedValue).HasMaxLength(1024);
        builder.Property(f => f.CisReference).HasMaxLength(128);

        builder.HasOne(f => f.Snapshot)
            .WithMany(s => s.Findings)
            .HasForeignKey(f => f.SnapshotId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}