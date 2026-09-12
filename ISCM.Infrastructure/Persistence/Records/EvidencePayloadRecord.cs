namespace ISCM.Infrastructure.Persistence.Records;

/// <summary>
/// Persistence record for deep evidence payloads.
/// Stores the full ControlResult -> SubControlResult -> Evidence tree as JSON.
/// Used for audit, detailed UI views, and snapshot diffing.
/// </summary>
public class EvidencePayloadRecord
{
    public Guid Id { get; set; }
    public Guid SnapshotId { get; set; }

    public string ControlId { get; set; } = string.Empty;
    public string SubControlId { get; set; } = string.Empty;

    /// <summary>
    /// JSON serialized representation of the SubControlResult and its Evidence items.
    /// Polymorphic EvidenceValue types are handled by custom JsonConverters (Phase 13.4).
    /// </summary>
    public string PayloadJson { get; set; } = string.Empty;

    // Navigation
    public SnapshotRecord Snapshot { get; set; } = null!;
}