using ISCM.Domain.Enums;

namespace ISCM.Application.Snapshots;

/// <summary>
/// Immutable snapshot of a single piece of evidence.
/// 
/// Design note: Stores the value as string for schema stability.
/// The EvidenceValueType enum indicates how to interpret the value.
/// This avoids polymorphic JSON complexity at the snapshot level.
/// Full polymorphic reconstruction happens in the persistence layer
/// when mapping to/from Domain.Evidence.
/// </summary>
public sealed class EvidenceSnapshot
{
    public string EvidenceId { get; init; } = string.Empty;
    public string SubControlId { get; init; } = string.Empty;
    public string TechnicalCheckId { get; init; } = string.Empty;
    public string? PathId { get; init; }

    // Source & Provenance
    public EvidenceSourceType SourceType { get; init; }
    public string SourceName { get; init; } = string.Empty;
    public string AcquisitionCommand { get; init; } = string.Empty;
    public string? AcquisitionArguments { get; init; }
    public string MachineIdentity { get; init; } = string.Empty;
    public DateTime CollectedAtUtc { get; init; }
    public int CollectionDurationMs { get; init; }

    // Values (stored as normalized strings for schema stability)
    public string? RawOutput { get; init; }
    public string? ParsedValue { get; init; }
    public string? NormalizedValue { get; init; }
    public string? ExpectedValue { get; init; }
    public EvidenceValueType ValueType { get; init; }

    // Evaluation
    public CheckStatus Evaluation { get; init; }
    public string? EvaluationReason { get; init; }
    public string? Error { get; init; }

    // Integrity
    public string Fingerprint { get; init; } = string.Empty;

    // Lifecycle
    public EvidenceLifecycleState LifecycleState { get; init; }

    public override string ToString()
        => $"{EvidenceId} [{SourceType}] {NormalizedValue ?? "(null)"}";
}