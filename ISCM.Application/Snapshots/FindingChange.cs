using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Represents a change at the finding level between two snapshots.
/// Findings are the flattened view of control results.
/// </summary>
public sealed class FindingChange
{
    public string CheckId { get; init; } = string.Empty;
    public string? SubControlId { get; init; }
    public string Name { get; init; } = string.Empty;
    public ChangeType ChangeType { get; init; }

    public CheckStatus? OldStatus { get; init; }
    public CheckStatus? NewStatus { get; init; }

    public string? OldCurrentValue { get; init; }
    public string? NewCurrentValue { get; init; }

    public override string ToString()
        => $"{CheckId} [{ChangeType}]: {OldStatus} → {NewStatus}";
}