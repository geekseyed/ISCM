using ISCM.Application.Snapshots;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Semantic comparison engine for scan snapshots.
/// 
/// Phase 13.2: Provides domain-level diff semantics rather than
/// naive JSON/string comparison. Understands compliance concepts
/// like "Improved", "Regressed", "Added Control", "Removed Control".
/// 
/// Design principles:
/// - Uses canonical status ordering (Error > Fail > Unknown > Pass)
/// - Detects semantic changes, not just textual differences
/// - Evidence comparison uses fingerprints and normalized values
/// - Application-level service; does not depend on persistence
/// 
/// This engine is essential for:
/// - Before/after remediation verification
/// - Compliance drift detection
/// - Historical trend reporting
/// - Executive summary generation
/// </summary>
public interface ISnapshotDiffEngine
{
    /// <summary>
    /// Compares two snapshots and produces a semantic diff result.
    /// 
    /// Contract:
    /// - Both snapshots must be non-null
    /// - sourceSnapshot is the "before" state
    /// - targetSnapshot is the "after" state
    /// - Comparison is performed at Control, SubControl, and Evidence levels
    /// </summary>
    /// <param name="sourceSnapshot">The baseline snapshot (before)</param>
    /// <param name="targetSnapshot">The comparison snapshot (after)</param>
    /// <returns>A structured diff result with semantic change classifications</returns>
    /// <exception cref="ArgumentNullException">If either snapshot is null</exception>
    SnapshotDiffResult Compare(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot);

    /// <summary>
    /// Compares two snapshots asynchronously. Suitable for large snapshots
    /// where the comparison may take measurable time.
    /// </summary>
    Task<SnapshotDiffResult> CompareAsync(
        ScanSnapshot sourceSnapshot,
        ScanSnapshot targetSnapshot,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Detects regressions between two snapshots.
    /// A regression is any transition that worsens compliance posture.
    /// </summary>
    /// <param name="sourceSnapshot">The baseline snapshot</param>
    /// <param name="targetSnapshot">The comparison snapshot</param>
    /// <returns>True if any regression is detected</returns>
    bool HasRegressions(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot);

    /// <summary>
    /// Detects improvements between two snapshots.
    /// An improvement is any transition that strengthens compliance posture.
    /// </summary>
    bool HasImprovements(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot);

    /// <summary>
    /// Determines whether two snapshots represent the same compliance state.
    /// Uses semantic comparison, not reference or string equality.
    /// </summary>
    bool AreEquivalent(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot);
}