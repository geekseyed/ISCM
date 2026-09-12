using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Lightweight snapshot metadata for efficient list rendering.
/// Does not include full control/evidence payloads.
/// </summary>
public sealed class SnapshotSummary
{
    public Guid SnapshotId { get; init; }
    public string ScanId { get; init; } = string.Empty;
    public string AssetId { get; init; } = string.Empty;
    public string Hostname { get; init; } = string.Empty;
    public string OsVersion { get; init; } = string.Empty;
    public DateTime CompletedAtUtc { get; init; }
    public string Grade { get; init; } = string.Empty;
    public int ComplianceScore { get; init; }
    public CheckStatus OverallStatus { get; init; }
    public int PassCount { get; init; }
    public int FailCount { get; init; }
    public int TotalControlCount { get; init; }

    public override string ToString()
        => $"{Hostname} @ {CompletedAtUtc:yyyy-MM-dd HH:mm} - {Grade} ({ComplianceScore}%)";
}