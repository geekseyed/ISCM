namespace ISCM.Domain.Enums;

/// <summary>
/// Lifecycle state of evidence.
/// </summary>
public enum EvidenceLifecycleState
{
    Live = 0,
    Cached = 1,
    Historical = 2,
    RemediationGenerated = 3,
    Invalidated = 4
}