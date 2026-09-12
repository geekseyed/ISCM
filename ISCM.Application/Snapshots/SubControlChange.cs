using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Represents a change at the sub-control level between two snapshots.
/// This is the most granular change unit and the primary input for
/// remediation verification and drift detection.
/// </summary>
public sealed class SubControlChange
{
    public string SubControlId { get; init; } = string.Empty;
    public string ParentControlId { get; init; } = string.Empty;
    public ChangeType ChangeType { get; init; }

    public CheckStatus? OldStatus { get; init; }
    public CheckStatus? NewStatus { get; init; }

    public string? OldActualValue { get; init; }
    public string? NewActualValue { get; init; }

    public string? OldReason { get; init; }
    public string? NewReason { get; init; }

    /// <summary>
    /// Evidence-level changes within this sub-control.
    /// </summary>
    public IReadOnlyList<EvidenceChange> EvidenceChanges { get; init; } = Array.Empty<EvidenceChange>();

    /// <summary>
    /// Human-readable description of the change.
    /// </summary>
    public string Description
    {
        get
        {
            return ChangeType switch
            {
                ChangeType.Added => $"Sub-control {SubControlId} added with status {NewStatus}",
                ChangeType.Removed => $"Sub-control {SubControlId} removed (was {OldStatus})",
                ChangeType.Improved => $"Sub-control {SubControlId} improved: {OldStatus} → {NewStatus}",
                ChangeType.Regressed => $"Sub-control {SubControlId} regressed: {OldStatus} → {NewStatus}",
                ChangeType.Changed => $"Sub-control {SubControlId} changed (status unchanged: {OldStatus})",
                ChangeType.Unchanged => $"Sub-control {SubControlId} unchanged",
                _ => $"Sub-control {SubControlId}: {ChangeType}"
            };
        }
    }

    public override string ToString()
        => $"{SubControlId} [{ChangeType}]: {OldStatus} → {NewStatus}";
}