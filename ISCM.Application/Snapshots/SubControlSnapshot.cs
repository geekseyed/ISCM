using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable snapshot of a sub-control-level result.
/// The most granular evaluation unit in the snapshot.
/// </summary>
public sealed class SubControlSnapshot
{
    public string SubControlId { get; init; } = string.Empty;
    public string ParentControlId { get; init; } = string.Empty;
    public CheckStatus Status { get; init; }
    public DateTime EvaluatedAt { get; init; }

    /// <summary>
    /// Expected value from the baseline/catalog.
    /// Stored as string for schema stability across type evolution.
    /// </summary>
    public string? ExpectedValue { get; init; }

    /// <summary>
    /// Actual value observed on the system.
    /// Stored as string for schema stability.
    /// </summary>
    public string? ActualValue { get; init; }

    /// <summary>
    /// Human-readable evaluation reason (e.g., "Integer 0 is less than 14").
    /// </summary>
    public string? EvaluationReason { get; init; }

    /// <summary>
    /// Operator used for comparison (e.g., ">=", "==", "Contains").
    /// </summary>
    public string? Operator { get; init; }

    /// <summary>
    /// Evidence items associated with this sub-control. Immutable collection.
    /// </summary>
    public IReadOnlyList<EvidenceSnapshot> EvidenceItems { get; init; } = Array.Empty<EvidenceSnapshot>();

    public override string ToString()
        => $"{SubControlId} [{Status}] = {ActualValue ?? "(null)"}";
}