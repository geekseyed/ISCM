using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Represents a change at the control level between two snapshots.
/// </summary>
public sealed class ControlChange
{
    public string ControlId { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public ChangeType ChangeType { get; init; }

    public CheckStatus? OldStatus { get; init; }
    public CheckStatus? NewStatus { get; init; }

    public int OldPassCount { get; init; }
    public int NewPassCount { get; init; }
    public int OldFailCount { get; init; }
    public int NewFailCount { get; init; }

    /// <summary>
    /// Sub-control changes within this control.
    /// Empty for Added/Removed controls.
    /// </summary>
    public IReadOnlyList<SubControlChange> SubControlChanges { get; init; } = Array.Empty<SubControlChange>();

    public override string ToString()
        => $"{ControlId} [{ChangeType}]: {OldStatus} → {NewStatus}";
}