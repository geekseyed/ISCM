using System;
using ISCM.Domain.Common;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents a single piece of evidence collected during a scan.
/// Each Evidence is scoped to a specific Scan, SubControl, and Verification Path.
/// Evidence is immutable once created - it represents a snapshot of system state.
/// </summary>
public class Evidence : BaseEntity
{
    // === IDENTITY ===

    public string EvidenceId { get; set; } = Guid.NewGuid().ToString();

    public string ScanId { get; set; } = string.Empty;

    public string ParentControlId { get; set; } = string.Empty;

    public string SubControlId { get; set; } = string.Empty;

    public string? PathId { get; set; }

    public string TechnicalCheckId { get; set; } = string.Empty;

    // === SOURCE & PROVENANCE ===

    public EvidenceSourceType SourceType { get; set; } = EvidenceSourceType.Unknown;

    public string SourceName { get; set; } = string.Empty;

    public string AcquisitionCommand { get; set; } = string.Empty;

    public string? AcquisitionArguments { get; set; }

    public string MachineIdentity { get; set; } = string.Empty;

    public DateTime CollectedAtUtc { get; set; } = DateTime.UtcNow;

    public int CollectionDurationMs { get; set; }

    // === VALUES ===

    public string? RawOutput { get; set; }

    public string? ParsedValue { get; set; }

    public string? NormalizedValue { get; set; }

    public string? ExpectedValue { get; set; }

    public EvidenceValueType ValueType { get; set; } = EvidenceValueType.Unknown;

    // === EVALUATION ===

    public CheckStatus Evaluation { get; set; } = CheckStatus.NotScanned;

    public string EvaluationReason { get; set; } = string.Empty;

    public string? Error { get; set; }

    // === INTEGRITY ===

    public string Fingerprint { get; set; } = string.Empty;

    // === LIFECYCLE ===

    public EvidenceLifecycleState LifecycleState { get; set; } = EvidenceLifecycleState.Live;

    public DateTime? StateChangedAtUtc { get; set; }

    // === PROVENANCE (Phase 3.3) ===

    public EvidenceProvenance? Provenance { get; set; }

    // === TYPED VALUE (Phase 3.2) ===

    public EvidenceValue? TypedValue { get; set; }

    // === LIFECYCLE PROPERTIES ===

    public bool IsLive => LifecycleState == EvidenceLifecycleState.Live;

    public bool IsCached => LifecycleState == EvidenceLifecycleState.Cached;

    public bool IsHistorical => LifecycleState == EvidenceLifecycleState.Historical;

    public bool IsRemediationGenerated => LifecycleState == EvidenceLifecycleState.RemediationGenerated;

    public bool IsInvalidated => LifecycleState == EvidenceLifecycleState.Invalidated;

    public bool IsUsable => !IsInvalidated && (IsLive || IsRemediationGenerated);

    // === COMPUTED ===

    public void ComputeFingerprint()
    {
        var content = $"{ScanId}|{SubControlId}|{PathId}|{SourceType}|{SourceName}|{NormalizedValue}|{CollectedAtUtc:O}";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        Fingerprint = Convert.ToBase64String(sha256.ComputeHash(bytes));
    }

    public bool IsInScope(string scanId, string subControlId, string? pathId = null)
    {
        if (ScanId != scanId) return false;
        if (SubControlId != subControlId) return false;
        if (pathId != null && PathId != pathId) return false;
        return true;
    }

    // === LIFECYCLE TRANSITIONS ===

    public void MarkAsCached()
    {
        LifecycleState = EvidenceLifecycleState.Cached;
        StateChangedAtUtc = DateTime.UtcNow;
    }

    public void MarkAsHistorical()
    {
        LifecycleState = EvidenceLifecycleState.Historical;
        StateChangedAtUtc = DateTime.UtcNow;
    }

    public void MarkAsRemediationGenerated()
    {
        LifecycleState = EvidenceLifecycleState.RemediationGenerated;
        StateChangedAtUtc = DateTime.UtcNow;
    }

    public void Invalidate()
    {
        LifecycleState = EvidenceLifecycleState.Invalidated;
        StateChangedAtUtc = DateTime.UtcNow;
    }
}