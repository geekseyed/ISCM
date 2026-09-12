using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable snapshot of a control-level result.
/// Part of the ScanSnapshot aggregate.
/// </summary>
public sealed class ControlSnapshot
{
    public string ControlId { get; init; } = string.Empty;
    public string ParentControlId { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public CheckCategory Category { get; init; }
    public CheckSeverity Severity { get; init; }
    public CheckStatus Status { get; init; }
    public DateTime EvaluatedAt { get; init; }

    /// <summary>
    /// Sub-control results within this control. Immutable collection.
    /// </summary>
    public IReadOnlyList<SubControlSnapshot> SubControls { get; init; } = Array.Empty<SubControlSnapshot>();

    // =========================================================================
    // Query Helpers
    // =========================================================================

    public SubControlSnapshot? FindSubControl(string subControlId)
        => SubControls.FirstOrDefault(s => s.SubControlId == subControlId);

    public int PassCount => SubControls.Count(s => s.Status == CheckStatus.Pass);
    public int FailCount => SubControls.Count(s => s.Status == CheckStatus.Fail);
    public int WarningCount => SubControls.Count(s => s.Status == CheckStatus.Unknown);

    public override string ToString()
        => $"{ControlId} [{Status}] - {Title}";
}