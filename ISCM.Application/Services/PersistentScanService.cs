using ISCM.Application.Interfaces;
using ISCM.Application.Snapshots;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

/// <summary>
/// Decorator around IScanService that automatically persists completed scans
/// as immutable ScanSnapshots.
/// 
/// Phase 13.6: Implements the Decorator Pattern to add persistence concerns
/// without modifying the underlying scanner implementation (WindowsHardeningScanner).
/// 
/// Flow:
///   1. Delegate scan execution to inner IScanService
///   2. On successful completion, map ScanResult to ScanSnapshot
///   3. Persist snapshot via ISnapshotRepository
///   4. Return original ScanResult to caller (UI unaware of persistence)
/// 
/// Rescan Behavior:
///   - RescanCheckAsync and RescanSubControlAsync do NOT create new snapshots
///   - They return updated Findings for in-memory UI updates
///   - Full snapshots are only created for complete scans (RunScanAsync)
/// 
/// Error Handling:
///   - Persistence failures are reported via IProgress but do NOT fail the scan
///   - User sees scan results even if persistence fails
///   - This ensures scanner availability is not compromised by storage issues
/// </summary>
public class PersistentScanService : IScanService
{
    private readonly IScanService _inner;
    private readonly ISnapshotRepository _snapshotRepository;
    private readonly ISnapshotMapper _snapshotMapper;

    public PersistentScanService(
        IScanService inner,
        ISnapshotRepository snapshotRepository,
        ISnapshotMapper snapshotMapper)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
        _snapshotMapper = snapshotMapper ?? throw new ArgumentNullException(nameof(snapshotMapper));
    }

    public int TotalCheckCount => _inner.TotalCheckCount;

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null)
    {
        // Step 1: Execute the actual scan via inner service
        var scanResult = await _inner.RunScanAsync(mode, progress);

        // Step 2: Only persist if scan completed successfully
        if (scanResult.CompletedAtUtc.HasValue && scanResult.CompletedAtUtc.Value != default)
        {
            try
            {
                // Step 3: Map to immutable snapshot
                var snapshot = _snapshotMapper.ToSnapshot(scanResult);

                // Step 4: Persist to repository
                await _snapshotRepository.SaveAsync(snapshot);

                progress?.Report(
                    $"[INFO] Scan snapshot persisted: {snapshot.SnapshotId:N} | " +
                    $"Grade={snapshot.Grade} | Score={snapshot.ComplianceScore}%");
            }
            catch (Exception ex)
            {
                // Persistence failure should NOT fail the scan
                progress?.Report($"[WARNING] Failed to save snapshot: {ex.Message}");
            }
        }
        else
        {
            progress?.Report("[WARNING] Scan completed but CompletedAtUtc is not set; skipping snapshot persistence");
        }

        return scanResult;
    }

    public async Task<Finding> RescanCheckAsync(string checkId)
    {
        // Rescans do NOT create new snapshots; they update the current in-memory result
        // This avoids snapshot proliferation for partial verifications
        return await _inner.RescanCheckAsync(checkId);
    }

    public async Task<Finding> RescanSubControlAsync(string checkId, string subControlId)
    {
        // Same as RescanCheckAsync - no snapshot for partial rescans
        return await _inner.RescanSubControlAsync(checkId, subControlId);
    }
}