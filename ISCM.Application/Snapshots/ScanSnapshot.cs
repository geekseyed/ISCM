using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable historical record of a completed scan.
/// 
/// Phase 13.2: First-class domain concept representing a point-in-time
/// compliance assessment. Once persisted, a ScanSnapshot MUST NOT be modified.
/// 
/// Defined as a sealed record to support with-expressions for integrity hashing.
/// </summary>
public sealed record ScanSnapshot
{
    // =========================================================================
    // Identity
    // =========================================================================

    public Guid SnapshotId { get; init; }
    public string ScanId { get; init; } = string.Empty;
    public string AssetId { get; init; } = string.Empty;

    // =========================================================================
    // Asset / System Information
    // =========================================================================

    public string Hostname { get; init; } = string.Empty;
    public string IpAddress { get; init; } = string.Empty;
    public string MacAddress { get; init; } = string.Empty;
    public string OsVersion { get; init; } = string.Empty;
    public int OsBuild { get; init; }

    // =========================================================================
    // Scan Metadata
    // =========================================================================

    public ScanMode ScanMode { get; init; }
    public string? BaselineId { get; init; }
    public string? BaselineName { get; init; }
    public string? BaselineVersion { get; init; }
    public string ScannerVersion { get; init; } = string.Empty;

    // =========================================================================
    // Timing
    // =========================================================================

    public DateTime StartedAtUtc { get; init; }
    public DateTime CompletedAtUtc { get; init; }
    public TimeSpan Duration => CompletedAtUtc - StartedAtUtc;

    // =========================================================================
    // Overall Status & Compliance Metrics
    // =========================================================================

    public CheckStatus OverallStatus { get; init; }
    public int ComplianceScore { get; init; }
    public string Grade { get; init; } = string.Empty;
    public int PassCount { get; init; }
    public int FailCount { get; init; }
    public int WarningCount { get; init; }
    public int ErrorCount { get; init; }
    public int TotalControlCount { get; init; }
    public int TotalSubControlCount { get; init; }

    // =========================================================================
    // Content (Immutable Collections)
    // =========================================================================

    public IReadOnlyList<ControlSnapshot> Controls { get; init; } = Array.Empty<ControlSnapshot>();
    public IReadOnlyList<FindingSnapshot> Findings { get; init; } = Array.Empty<FindingSnapshot>();

    // =========================================================================
    // Integrity
    // =========================================================================

    public string IntegrityHash { get; init; } = string.Empty;
    public int SchemaVersion { get; init; } = 1;

    // =========================================================================
    // Constructor
    // =========================================================================

    public ScanSnapshot()
    {
        SnapshotId = Guid.NewGuid();
    }

    // =========================================================================
    // Query Helpers
    // =========================================================================

    public ControlSnapshot? FindControl(string controlId)
        => Controls.FirstOrDefault(c => c.ControlId == controlId);

    public SubControlSnapshot? FindSubControl(string subControlId)
        => Controls
            .SelectMany(c => c.SubControls)
            .FirstOrDefault(s => s.SubControlId == subControlId);

    public FindingSnapshot? FindFinding(string checkId, string? subControlId = null)
        => Findings.FirstOrDefault(f =>
            f.CheckId == checkId &&
            (subControlId == null || f.SubControlId == subControlId));

    public IEnumerable<FindingSnapshot> GetFailedFindings()
        => Findings.Where(f => f.Status == CheckStatus.Fail);

    public IEnumerable<FindingSnapshot> GetFindingsBySeverity(CheckSeverity severity)
        => Findings.Where(f => f.Severity == severity);

    public override string ToString()
        => $"Snapshot {SnapshotId:N} | {Hostname} | {CompletedAtUtc:yyyy-MM-dd HH:mm} | {Grade} ({ComplianceScore}%)";
}