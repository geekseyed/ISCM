namespace ISCM.Infrastructure.Persistence.Records;

/// <summary>
/// Persistence record for scan snapshots.
/// Optimized for querying history, filtering by asset, and sorting by date.
/// </summary>
public class SnapshotRecord
{
    public Guid Id { get; set; }
    public string ScanId { get; set; } = string.Empty;
    public string AssetId { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public int OsBuild { get; set; }
    public string ScanMode { get; set; } = string.Empty;
    public string? BaselineId { get; set; }
    public string? BaselineName { get; set; }
    public string ScannerVersion { get; set; } = string.Empty;

    public DateTime StartedAtUtc { get; set; }
    public DateTime CompletedAtUtc { get; set; }

    public string OverallStatus { get; set; } = string.Empty;
    public int ComplianceScore { get; set; }
    public string Grade { get; set; } = string.Empty;
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public int TotalControlCount { get; set; }
    public int TotalSubControlCount { get; set; }

    public string IntegrityHash { get; set; } = string.Empty;
    public int SchemaVersion { get; set; }
    public DateTime PersistedAtUtc { get; set; }

    // Navigation properties
    public List<FindingRecord> Findings { get; set; } = new();
    public List<EvidencePayloadRecord> EvidencePayloads { get; set; } = new();
}