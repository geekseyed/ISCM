namespace ISCM.Application.Snapshots;

/// <summary>
/// Represents a change at the evidence level between two snapshots.
/// </summary>
public sealed class EvidenceChange
{
    public string EvidenceId { get; init; } = string.Empty;
    public string SubControlId { get; init; } = string.Empty;
    public ChangeType ChangeType { get; init; }

    public string? OldFingerprint { get; init; }
    public string? NewFingerprint { get; init; }

    public string? OldNormalizedValue { get; init; }
    public string? NewNormalizedValue { get; init; }

    public bool FingerprintChanged =>
        !string.Equals(OldFingerprint, NewFingerprint, StringComparison.Ordinal);

    public override string ToString()
        => $"Evidence {EvidenceId} [{ChangeType}]: {OldNormalizedValue} → {NewNormalizedValue}";
}