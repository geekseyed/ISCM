using ISCM.Application.Snapshots;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Bidirectional mapper between live ScanResult and immutable ScanSnapshot.
/// 
/// Phase 13.2: Separates mapping concerns from persistence implementation.
/// The mapper is responsible for:
/// - "Freezing" a live ScanResult into an immutable ScanSnapshot
/// - Reconstructing a ScanResult from a persisted ScanSnapshot
/// - Computing integrity hashes
/// - Preserving all domain semantics and relationships
/// 
/// Design principles:
/// - Pure transformation; no I/O or persistence logic
/// - Deterministic: same input always produces same output
/// - Lossless: no domain data is dropped during mapping
/// - Immutable output: ScanSnapshot cannot be mutated after creation
/// </summary>
public interface ISnapshotMapper
{
    /// <summary>
    /// Converts a completed ScanResult into an immutable ScanSnapshot.
    /// 
    /// Contract:
    /// - ScanResult must be completed (CompletedAtUtc has value)
    /// - Produces a new ScanSnapshot with a new SnapshotId (Guid)
    /// - Preserves the original ScanId as correlation identifier
    /// - Computes integrity hash from all content
    /// - Deep-copies all collections to prevent mutation
    /// </summary>
    /// <param name="scanResult">The completed scan result</param>
    /// <param name="assetId">Optional asset identifier (defaults to hostname)</param>
    /// <returns>A new immutable ScanSnapshot</returns>
    /// <exception cref="ArgumentNullException">If scanResult is null</exception>
    /// <exception cref="InvalidOperationException">If scanResult is not completed</exception>
    ScanSnapshot ToSnapshot(ScanResult scanResult, string? assetId = null);

    /// <summary>
    /// Reconstructs a ScanResult from a persisted ScanSnapshot.
    /// 
    /// Use cases:
    /// - Displaying historical scan data in the UI
    /// - Performing diff operations
    /// - Exporting to reports
    /// 
    /// Note: The reconstructed ScanResult is a read-only view.
    /// Any modifications will not affect the persisted snapshot.
    /// </summary>
    /// <param name="snapshot">The persisted snapshot</param>
    /// <returns>A reconstructed ScanResult</returns>
    /// <exception cref="ArgumentNullException">If snapshot is null</exception>
    ScanResult ToScanResult(ScanSnapshot snapshot);

    /// <summary>
    /// Computes the integrity hash for a snapshot.
    /// Uses SHA-256 over a canonical representation of all content.
    /// </summary>
    string ComputeIntegrityHash(ScanSnapshot snapshot);

    /// <summary>
    /// Verifies that a snapshot's integrity hash matches its content.
    /// </summary>
    bool VerifyIntegrity(ScanSnapshot snapshot);
}