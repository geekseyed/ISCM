namespace ISCM.Infrastructure.Persistence.Records;

/// <summary>
/// Persistence record for findings.
/// Stored as a flat relational table for fast querying, filtering, and reporting
/// without needing to deserialize the full evidence payload.
/// </summary>
public class FindingRecord
{
    public Guid Id { get; set; }
    public Guid SnapshotId { get; set; }

    public string CheckId { get; set; } = string.Empty;
    public string? SubControlId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;

    public string CurrentValue { get; set; } = string.Empty;
    public string ExpectedValue { get; set; } = string.Empty;
    public string CisReference { get; set; } = string.Empty;
    public int RiskScore { get; set; }

    public bool IsSuppressed { get; set; }
    public bool IsFalsePositive { get; set; }

    // Navigation
    public SnapshotRecord Snapshot { get; set; } = null!;
}