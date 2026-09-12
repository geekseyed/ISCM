using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable snapshot of a Finding.
/// 
/// Findings are the flattened, human-readable representation of control results.
/// Stored separately from the control hierarchy for efficient querying and reporting.
/// </summary>
public sealed class FindingSnapshot
{
    public string CheckId { get; init; } = string.Empty;
    public string? SubControlId { get; init; }
    public string Name { get; init; } = string.Empty;
    public CheckCategory Category { get; init; }
    public CheckSeverity Severity { get; init; }
    public CheckStatus Status { get; init; }
    public string CurrentValue { get; init; } = string.Empty;
    public string ExpectedValue { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string? RegistryPath { get; init; }
    public string Recommendation { get; init; } = string.Empty;
    public string? ErrorMessage { get; init; }
    public string CisReference { get; init; } = string.Empty;
    public int RiskScore { get; init; }
    public string SourceType { get; init; } = string.Empty;
    public string SourceCommand { get; init; } = string.Empty;

    // Governance state at time of snapshot
    public bool IsSuppressed { get; init; }
    public string? IgnoreReason { get; init; }
    public string? IgnoredBy { get; init; }
    public DateTime? IgnoredAt { get; init; }
    public bool IsFalsePositive { get; init; }

    public override string ToString()
        => $"{CheckId}{(SubControlId != null ? $"[{SubControlId}]" : "")} [{Status}] - {Name}";
}