namespace ISCM.Application.Snapshots;

/// <summary>
/// Result of comparing two scan snapshots.
/// Provides semantic change classifications at multiple granularity levels.
/// </summary>
public sealed class SnapshotDiffResult
{
    // =========================================================================
    // Source Snapshots
    // =========================================================================

    public Guid SourceSnapshotId { get; init; }
    public Guid TargetSnapshotId { get; init; }
    public DateTime SourceCompletedAt { get; init; }
    public DateTime TargetCompletedAt { get; init; }
    public TimeSpan TimeBetweenScans => TargetCompletedAt - SourceCompletedAt;

    // =========================================================================
    // Overall Change Summary
    // =========================================================================

    /// <summary>
    /// Net change in compliance score (target - source).
    /// Positive = improvement, Negative = regression.
    /// </summary>
    public int ComplianceScoreDelta { get; init; }

    public int PassCountDelta { get; init; }
    public int FailCountDelta { get; init; }
    public int WarningCountDelta { get; init; }

    /// <summary>
    /// Overall semantic verdict for the diff.
    /// </summary>
    public DiffVerdict OverallVerdict { get; init; }

    // =========================================================================
    // Change Classifications
    // =========================================================================

    public DiffSummary Summary { get; init; } = new();
    public IReadOnlyList<ControlChange> ControlChanges { get; init; } = Array.Empty<ControlChange>();
    public IReadOnlyList<SubControlChange> SubControlChanges { get; init; } = Array.Empty<SubControlChange>();
    public IReadOnlyList<FindingChange> FindingChanges { get; init; } = Array.Empty<FindingChange>();

    // =========================================================================
    // Query Helpers
    // =========================================================================

    public bool HasChanges =>
        Summary.Added > 0 || Summary.Removed > 0 ||
        Summary.Improved > 0 || Summary.Regressed > 0 ||
        Summary.Changed > 0;

    public bool HasRegressions => Summary.Regressed > 0;
    public bool HasImprovements => Summary.Improved > 0;

    public IEnumerable<SubControlChange> GetRegressions()
        => SubControlChanges.Where(c => c.ChangeType == ChangeType.Regressed);

    public IEnumerable<SubControlChange> GetImprovements()
        => SubControlChanges.Where(c => c.ChangeType == ChangeType.Improved);

    public IEnumerable<SubControlChange> GetNewFailures()
        => SubControlChanges.Where(c =>
            c.ChangeType == ChangeType.Regressed &&
            c.NewStatus == ISCM.Domain.Enums.CheckStatus.Fail);

    public override string ToString()
    {
        if (!HasChanges)
            return "No changes detected";

        return $"{OverallVerdict}: {Summary.Improved} improved, {Summary.Regressed} regressed, " +
               $"{Summary.Added} added, {Summary.Removed} removed, {Summary.Changed} changed, " +
               $"{Summary.Unchanged} unchanged";
    }
}

/// <summary>
/// Aggregate counts of change types across all levels.
/// </summary>
public sealed class DiffSummary
{
    /// <summary>Controls/subcontrols present in target but not source.</summary>
    public int Added { get; set; }

    /// <summary>Controls/subcontrols present in source but not target.</summary>
    public int Removed { get; set; }

    /// <summary>Controls/subcontrols that improved (e.g., Fail → Pass).</summary>
    public int Improved { get; set; }

    /// <summary>Controls/subcontrols that regressed (e.g., Pass → Fail).</summary>
    public int Regressed { get; set; }

    /// <summary>Controls/subcontrols with changed evidence but same status.</summary>
    public int Changed { get; set; }

    /// <summary>Controls/subcontrols with identical status and evidence.</summary>
    public int Unchanged { get; set; }

    public int TotalChanges => Added + Removed + Improved + Regressed + Changed;
}

/// <summary>
/// Overall verdict for a snapshot diff.
/// </summary>
public enum DiffVerdict
{
    /// <summary>No changes detected.</summary>
    Identical,

    /// <summary>All changes are improvements.</summary>
    Improved,

    /// <summary>Mix of improvements and regressions.</summary>
    Mixed,

    /// <summary>All changes are regressions.</summary>
    Regressed,

    /// <summary>Changes in evidence but no status changes.</summary>
    Drifted,

    /// <summary>New controls added (e.g., baseline update).</summary>
    BaselineChanged
}