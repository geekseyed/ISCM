using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Semantic comparison engine for scan snapshots.
/// 
/// Phase 13.7: Implements ISnapshotDiffEngine to detect compliance changes
/// between two snapshots using canonical status ordering (Error > Fail > Unknown > Pass).
/// 
/// Change classifications:
/// - Added: Control/SubControl exists in target but not source
/// - Removed: Control/SubControl exists in source but not target
/// - Improved: Status transitioned to better state (e.g., Fail → Pass)
/// - Regressed: Status transitioned to worse state (e.g., Pass → Fail)
/// - Changed: Evidence changed but status remained same
/// - Unchanged: Identical status and evidence
/// </summary>
public class SnapshotDiffEngine : ISnapshotDiffEngine
{
    public SnapshotDiffResult Compare(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot)
    {
        if (sourceSnapshot == null) throw new ArgumentNullException(nameof(sourceSnapshot));
        if (targetSnapshot == null) throw new ArgumentNullException(nameof(targetSnapshot));

        var controlChanges = CompareControls(sourceSnapshot.Controls, targetSnapshot.Controls);
        var subControlChanges = CompareSubControls(sourceSnapshot, targetSnapshot);
        var findingChanges = CompareFindings(sourceSnapshot.Findings, targetSnapshot.Findings);

        var summary = new DiffSummary
        {
            Added = subControlChanges.Count(c => c.ChangeType == ChangeType.Added),
            Removed = subControlChanges.Count(c => c.ChangeType == ChangeType.Removed),
            Improved = subControlChanges.Count(c => c.ChangeType == ChangeType.Improved),
            Regressed = subControlChanges.Count(c => c.ChangeType == ChangeType.Regressed),
            Changed = subControlChanges.Count(c => c.ChangeType == ChangeType.Changed),
            Unchanged = subControlChanges.Count(c => c.ChangeType == ChangeType.Unchanged)
        };

        var overallVerdict = ComputeOverallVerdict(summary, sourceSnapshot, targetSnapshot);

        return new SnapshotDiffResult
        {
            SourceSnapshotId = sourceSnapshot.SnapshotId,
            TargetSnapshotId = targetSnapshot.SnapshotId,
            SourceCompletedAt = sourceSnapshot.CompletedAtUtc,
            TargetCompletedAt = targetSnapshot.CompletedAtUtc,
            ComplianceScoreDelta = targetSnapshot.ComplianceScore - sourceSnapshot.ComplianceScore,
            PassCountDelta = targetSnapshot.PassCount - sourceSnapshot.PassCount,
            FailCountDelta = targetSnapshot.FailCount - sourceSnapshot.FailCount,
            WarningCountDelta = targetSnapshot.WarningCount - sourceSnapshot.WarningCount,
            OverallVerdict = overallVerdict,
            Summary = summary,
            ControlChanges = controlChanges,
            SubControlChanges = subControlChanges,
            FindingChanges = findingChanges
        };
    }

    public Task<SnapshotDiffResult> CompareAsync(
        ScanSnapshot sourceSnapshot,
        ScanSnapshot targetSnapshot,
        CancellationToken cancellationToken = default)
    {
        // For now, synchronous implementation is sufficient
        // Can be made truly async if snapshots become very large
        return Task.FromResult(Compare(sourceSnapshot, targetSnapshot));
    }

    public bool HasRegressions(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot)
    {
        var result = Compare(sourceSnapshot, targetSnapshot);
        return result.Summary.Regressed > 0;
    }

    public bool HasImprovements(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot)
    {
        var result = Compare(sourceSnapshot, targetSnapshot);
        return result.Summary.Improved > 0;
    }

    public bool AreEquivalent(ScanSnapshot sourceSnapshot, ScanSnapshot targetSnapshot)
    {
        var result = Compare(sourceSnapshot, targetSnapshot);
        return !result.HasChanges;
    }

    // =========================================================================
    // Control-Level Comparison
    // =========================================================================

    private IReadOnlyList<ControlChange> CompareControls(
        IReadOnlyList<ControlSnapshot> sourceControls,
        IReadOnlyList<ControlSnapshot> targetControls)
    {
        var changes = new List<ControlChange>();

        var sourceDict = sourceControls.ToDictionary(c => c.ControlId);
        var targetDict = targetControls.ToDictionary(c => c.ControlId);

        // Check for removed controls
        foreach (var sourceControl in sourceControls)
        {
            if (!targetDict.ContainsKey(sourceControl.ControlId))
            {
                changes.Add(new ControlChange
                {
                    ControlId = sourceControl.ControlId,
                    Title = sourceControl.Title,
                    ChangeType = ChangeType.Removed,
                    OldStatus = sourceControl.Status,
                    NewStatus = null,
                    OldPassCount = sourceControl.PassCount,
                    NewPassCount = 0,
                    OldFailCount = sourceControl.FailCount,
                    NewFailCount = 0
                });
            }
        }

        // Check for added and changed controls
        foreach (var targetControl in targetControls)
        {
            if (!sourceDict.TryGetValue(targetControl.ControlId, out var sourceControl))
            {
                changes.Add(new ControlChange
                {
                    ControlId = targetControl.ControlId,
                    Title = targetControl.Title,
                    ChangeType = ChangeType.Added,
                    OldStatus = null,
                    NewStatus = targetControl.Status,
                    OldPassCount = 0,
                    NewPassCount = targetControl.PassCount,
                    OldFailCount = 0,
                    NewFailCount = targetControl.FailCount
                });
            }
            else
            {
                // Control exists in both - check for changes
                var controlChangeType = DetermineControlChangeType(sourceControl, targetControl);
                if (controlChangeType != ChangeType.Unchanged)
                {
                    changes.Add(new ControlChange
                    {
                        ControlId = targetControl.ControlId,
                        Title = targetControl.Title,
                        ChangeType = controlChangeType,
                        OldStatus = sourceControl.Status,
                        NewStatus = targetControl.Status,
                        OldPassCount = sourceControl.PassCount,
                        NewPassCount = targetControl.PassCount,
                        OldFailCount = sourceControl.FailCount,
                        NewFailCount = targetControl.FailCount
                    });
                }
            }
        }

        return changes;
    }

    // =========================================================================
    // SubControl-Level Comparison (Most Granular)
    // =========================================================================

    private IReadOnlyList<SubControlChange> CompareSubControls(
        ScanSnapshot sourceSnapshot,
        ScanSnapshot targetSnapshot)
    {
        var changes = new List<SubControlChange>();

        var sourceSubControls = sourceSnapshot.Controls
            .SelectMany(c => c.SubControls)
            .ToDictionary(s => s.SubControlId);

        var targetSubControls = targetSnapshot.Controls
            .SelectMany(c => c.SubControls)
            .ToDictionary(s => s.SubControlId);

        // Check for removed subcontrols
        foreach (var sourceSub in sourceSubControls.Values)
        {
            if (!targetSubControls.ContainsKey(sourceSub.SubControlId))
            {
                changes.Add(new SubControlChange
                {
                    SubControlId = sourceSub.SubControlId,
                    ParentControlId = sourceSub.ParentControlId,
                    ChangeType = ChangeType.Removed,
                    OldStatus = sourceSub.Status,
                    NewStatus = null,
                    OldActualValue = sourceSub.ActualValue,
                    NewActualValue = null,
                    OldReason = sourceSub.EvaluationReason,
                    NewReason = null
                });
            }
        }

        // Check for added and changed subcontrols
        foreach (var targetSub in targetSubControls.Values)
        {
            if (!sourceSubControls.TryGetValue(targetSub.SubControlId, out var sourceSub))
            {
                changes.Add(new SubControlChange
                {
                    SubControlId = targetSub.SubControlId,
                    ParentControlId = targetSub.ParentControlId,
                    ChangeType = ChangeType.Added,
                    OldStatus = null,
                    NewStatus = targetSub.Status,
                    OldActualValue = null,
                    NewActualValue = targetSub.ActualValue,
                    OldReason = null,
                    NewReason = targetSub.EvaluationReason
                });
            }
            else
            {
                // SubControl exists in both - determine change type
                var changeType = DetermineSubControlChangeType(sourceSub, targetSub);

                if (changeType != ChangeType.Unchanged)
                {
                    var evidenceChanges = CompareEvidence(sourceSub.EvidenceItems, targetSub.EvidenceItems);

                    changes.Add(new SubControlChange
                    {
                        SubControlId = targetSub.SubControlId,
                        ParentControlId = targetSub.ParentControlId,
                        ChangeType = changeType,
                        OldStatus = sourceSub.Status,
                        NewStatus = targetSub.Status,
                        OldActualValue = sourceSub.ActualValue,
                        NewActualValue = targetSub.ActualValue,
                        OldReason = sourceSub.EvaluationReason,
                        NewReason = targetSub.EvaluationReason,
                        EvidenceChanges = evidenceChanges
                    });
                }
            }
        }

        return changes;
    }

    // =========================================================================
    // Finding-Level Comparison
    // =========================================================================

    private IReadOnlyList<FindingChange> CompareFindings(
        IReadOnlyList<FindingSnapshot> sourceFindings,
        IReadOnlyList<FindingSnapshot> targetFindings)
    {
        var changes = new List<FindingChange>();

        var sourceDict = sourceFindings.ToDictionary(f => $"{f.CheckId}:{f.SubControlId ?? ""}");
        var targetDict = targetFindings.ToDictionary(f => $"{f.CheckId}:{f.SubControlId ?? ""}");

        // Check for removed findings
        foreach (var sourceFinding in sourceFindings)
        {
            var key = $"{sourceFinding.CheckId}:{sourceFinding.SubControlId ?? ""}";
            if (!targetDict.ContainsKey(key))
            {
                changes.Add(new FindingChange
                {
                    CheckId = sourceFinding.CheckId,
                    SubControlId = sourceFinding.SubControlId,
                    Name = sourceFinding.Name,
                    ChangeType = ChangeType.Removed,
                    OldStatus = sourceFinding.Status,
                    NewStatus = null,
                    OldCurrentValue = sourceFinding.CurrentValue,
                    NewCurrentValue = null
                });
            }
        }

        // Check for added and changed findings
        foreach (var targetFinding in targetFindings)
        {
            var key = $"{targetFinding.CheckId}:{targetFinding.SubControlId ?? ""}";
            if (!sourceDict.TryGetValue(key, out var sourceFinding))
            {
                changes.Add(new FindingChange
                {
                    CheckId = targetFinding.CheckId,
                    SubControlId = targetFinding.SubControlId,
                    Name = targetFinding.Name,
                    ChangeType = ChangeType.Added,
                    OldStatus = null,
                    NewStatus = targetFinding.Status,
                    OldCurrentValue = null,
                    NewCurrentValue = targetFinding.CurrentValue
                });
            }
            else
            {
                var changeType = DetermineFindingChangeType(sourceFinding, targetFinding);
                if (changeType != ChangeType.Unchanged)
                {
                    changes.Add(new FindingChange
                    {
                        CheckId = targetFinding.CheckId,
                        SubControlId = targetFinding.SubControlId,
                        Name = targetFinding.Name,
                        ChangeType = changeType,
                        OldStatus = sourceFinding.Status,
                        NewStatus = targetFinding.Status,
                        OldCurrentValue = sourceFinding.CurrentValue,
                        NewCurrentValue = targetFinding.CurrentValue
                    });
                }
            }
        }

        return changes;
    }

    // =========================================================================
    // Evidence-Level Comparison
    // =========================================================================

    private IReadOnlyList<EvidenceChange> CompareEvidence(
        IReadOnlyList<EvidenceSnapshot> sourceEvidence,
        IReadOnlyList<EvidenceSnapshot> targetEvidence)
    {
        var changes = new List<EvidenceChange>();

        var sourceDict = sourceEvidence.ToDictionary(e => e.EvidenceId);
        var targetDict = targetEvidence.ToDictionary(e => e.EvidenceId);

        // Check for removed evidence
        foreach (var sourceEv in sourceEvidence)
        {
            if (!targetDict.ContainsKey(sourceEv.EvidenceId))
            {
                changes.Add(new EvidenceChange
                {
                    EvidenceId = sourceEv.EvidenceId,
                    SubControlId = sourceEv.SubControlId,
                    ChangeType = ChangeType.Removed,
                    OldFingerprint = sourceEv.Fingerprint,
                    NewFingerprint = null,
                    OldNormalizedValue = sourceEv.NormalizedValue,
                    NewNormalizedValue = null
                });
            }
        }

        // Check for added and changed evidence
        foreach (var targetEv in targetEvidence)
        {
            if (!sourceDict.TryGetValue(targetEv.EvidenceId, out var sourceEv))
            {
                changes.Add(new EvidenceChange
                {
                    EvidenceId = targetEv.EvidenceId,
                    SubControlId = targetEv.SubControlId,
                    ChangeType = ChangeType.Added,
                    OldFingerprint = null,
                    NewFingerprint = targetEv.Fingerprint,
                    OldNormalizedValue = null,
                    NewNormalizedValue = targetEv.NormalizedValue
                });
            }
            else
            {
                // Evidence exists in both - check if changed
                var fingerprintChanged = sourceEv.Fingerprint != targetEv.Fingerprint;
                var valueChanged = sourceEv.NormalizedValue != targetEv.NormalizedValue;

                if (fingerprintChanged || valueChanged)
                {
                    changes.Add(new EvidenceChange
                    {
                        EvidenceId = targetEv.EvidenceId,
                        SubControlId = targetEv.SubControlId,
                        ChangeType = ChangeType.Changed,
                        OldFingerprint = sourceEv.Fingerprint,
                        NewFingerprint = targetEv.Fingerprint,
                        OldNormalizedValue = sourceEv.NormalizedValue,
                        NewNormalizedValue = targetEv.NormalizedValue
                    });
                }
            }
        }

        return changes;
    }

    // =========================================================================
    // Change Type Determination Helpers
    // =========================================================================

    private ChangeType DetermineControlChangeType(
        ControlSnapshot source,
        ControlSnapshot target)
    {
        if (source.Status == target.Status &&
            source.PassCount == target.PassCount &&
            source.FailCount == target.FailCount)
        {
            return ChangeType.Unchanged;
        }

        var statusChange = DetermineStatusChange(source.Status, target.Status);
        return statusChange;
    }

    private ChangeType DetermineSubControlChangeType(
        SubControlSnapshot source,
        SubControlSnapshot target)
    {
        var statusChange = DetermineStatusChange(source.Status, target.Status);

        // If status unchanged, check if evidence changed
        if (statusChange == ChangeType.Unchanged)
        {
            var evidenceChanged = source.EvidenceItems.Count != target.EvidenceItems.Count ||
                                  !source.EvidenceItems.All(se =>
                                      target.EvidenceItems.Any(te =>
                                          te.EvidenceId == se.EvidenceId &&
                                          te.Fingerprint == se.Fingerprint));

            return evidenceChanged ? ChangeType.Changed : ChangeType.Unchanged;
        }

        return statusChange;
    }

    private ChangeType DetermineFindingChangeType(
        FindingSnapshot source,
        FindingSnapshot target)
    {
        var statusChange = DetermineStatusChange(source.Status, target.Status);

        if (statusChange == ChangeType.Unchanged)
        {
            var valueChanged = source.CurrentValue != target.CurrentValue;
            return valueChanged ? ChangeType.Changed : ChangeType.Unchanged;
        }

        return statusChange;
    }

    /// <summary>
    /// Determines change type based on status transition using canonical ordering:
    /// Error > Fail > Unknown > Pass
    /// 
    /// Improved: Status moved to better state (right in ordering)
    /// Regressed: Status moved to worse state (left in ordering)
    /// </summary>
    private ChangeType DetermineStatusChange(CheckStatus source, CheckStatus target)
    {
        if (source == target) return ChangeType.Unchanged;

        var sourceRank = GetStatusRank(source);
        var targetRank = GetStatusRank(target);

        // Higher rank = worse status
        // If target rank is lower, it's an improvement
        // If target rank is higher, it's a regression
        return targetRank < sourceRank ? ChangeType.Improved : ChangeType.Regressed;
    }

    /// <summary>
    /// Canonical status ordering: Error (worst) > Fail > Unknown > Pass (best)
    /// Lower rank = better status
    /// </summary>
    private int GetStatusRank(CheckStatus status) => status switch
    {
        CheckStatus.Pass => 0,
        CheckStatus.Unknown => 1,
        CheckStatus.Fail => 2,
        CheckStatus.Error => 3,
        CheckStatus.NotScanned => 4,
        CheckStatus.Ignored => 5,
        CheckStatus.FalsePositive => 6,
        _ => 99
    };

    // =========================================================================
    // Overall Verdict Computation
    // =========================================================================

    private DiffVerdict ComputeOverallVerdict(
    DiffSummary summary,
    ScanSnapshot sourceSnapshot,
    ScanSnapshot targetSnapshot)
    {
        // FIX: Use TotalChanges instead of HasChanges() method
        if (summary.TotalChanges == 0)
            return DiffVerdict.Identical;

        // Baseline changed (new controls added/removed)
        if (summary.Added > 0 || summary.Removed > 0)
        {
            if (summary.Improved == 0 && summary.Regressed == 0 && summary.Changed == 0)
                return DiffVerdict.BaselineChanged;
        }

        if (summary.Improved > 0 && summary.Regressed == 0)
            return DiffVerdict.Improved;

        if (summary.Regressed > 0 && summary.Improved == 0)
            return DiffVerdict.Regressed;

        if (summary.Improved > 0 && summary.Regressed > 0)
            return DiffVerdict.Mixed;

        if (summary.Changed > 0 && summary.Improved == 0 && summary.Regressed == 0)
            return DiffVerdict.Drifted;

        return DiffVerdict.Mixed;
    }
}