using ISCM.Infrastructure.Persistence.Records;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ISCM.Infrastructure.Persistence.Configurations;

public class EvidencePayloadConfiguration : IEntityTypeConfiguration<EvidencePayloadRecord>
{
    public void Configure(EntityTypeBuilder<EvidencePayloadRecord> builder)
    {
        builder.ToTable("EvidencePayloads");
        builder.HasKey(e => e.Id);

        builder.HasIndex(e => e.SnapshotId);
        builder.HasIndex(e => new { e.SnapshotId, e.SubControlId });

        builder.Property(e => e.ControlId).IsRequired().HasMaxLength(64);
        builder.Property(e => e.SubControlId).IsRequired().HasMaxLength(64);

        // PayloadJson can be large; SQLite stores it as TEXT natively
        builder.Property(e => e.PayloadJson).IsRequired();

        builder.HasOne(e => e.Snapshot)
            .WithMany(s => s.EvidencePayloads)
            .HasForeignKey(e => e.SnapshotId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}