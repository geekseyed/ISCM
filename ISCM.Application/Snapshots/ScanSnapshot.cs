using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable historical record of a completed scan.
/// 
/// Phase 13.2: First-class domain concept representing a point-in-time
/// compliance assessment. Once persisted, a ScanSnapshot MUST NOT be modified.
/// 
/// Design principles:
/// - Immutable after construction (readonly collections, init-only properties)
/// - Self-contained: contains all data needed for audit and diff operations
/// - Identifiable: has stable SnapshotId and correlation ScanId
/// - Verifiable: has integrity hash computed from all content
/// 
/// Lifecycle:
/// 1. Created by ISnapshotMapper from a completed ScanResult
/// 2. Persisted by ISnapshotRepository
/// 3. Read-only for all subsequent operations (UI, Diff, Reporting)
/// 4. Never modified; corrections produce new snapshots
/// 
/// Relationship to other concepts:
/// - ScanResult = live execution context (mutable during scan)
/// - ScanSnapshot = frozen historical record (immutable)
/// - Future ScanJob/Execution concepts will reference ScanSnapshot
/// </summary>
public sealed class ScanSnapshot
{
    // =========================================================================
    // Identity
    // =========================================================================

    /// <summary>
    /// Unique identifier for this snapshot (database-agnostic).
    /// Generated at creation time, stable for the lifetime of the snapshot.
    /// </summary>
    public Guid SnapshotId { get; init; }

    /// <summary>
    /// Original scan correlation identifier from ScanContext.
    /// Used for traceability back to the scan execution.
    /// </summary>
    public string ScanId { get; init; } = string.Empty;

    /// <summary>
    /// Asset identifier (typically hostname for Windows endpoints).
    /// Future: may become a proper AssetId when Asset Inventory (Phase 18) is introduced.
    /// </summary>
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

    /// <summary>
    /// Control-level results. Immutable snapshot of the control hierarchy.
    /// </summary>
    public IReadOnlyList<ControlSnapshot> Controls { get; init; } = Array.Empty<ControlSnapshot>();

    /// <summary>
    /// Flat list of findings for efficient querying and reporting.
    /// Derived from the control hierarchy but stored separately for performance.
    /// </summary>
    public IReadOnlyList<FindingSnapshot> Findings { get; init; } = Array.Empty<FindingSnapshot>();

    // =========================================================================
    // Integrity
    // =========================================================================

    /// <summary>
    /// SHA-256 hash computed over all content.
    /// Used to detect tampering or corruption of persisted snapshots.
    /// </summary>
    public string IntegrityHash { get; init; } = string.Empty;

    /// <summary>
    /// Version of the snapshot schema. Used for forward/backward compatibility
    /// when the snapshot structure evolves in future phases.
    /// </summary>
    public int SchemaVersion { get; init; } = 1;

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// <summary>
    /// Private constructor to enforce creation through factory/builder patterns.
    /// Use ISnapshotMapper.ToSnapshot() to create instances.
    /// </summary>
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

    // =========================================================================
    // Display Helpers
    // =========================================================================

    public override string ToString()
        => $"Snapshot {SnapshotId:N} | {Hostname} | {CompletedAtUtc:yyyy-MM-dd HH:mm} | {Grade} ({ComplianceScore}%)";
}