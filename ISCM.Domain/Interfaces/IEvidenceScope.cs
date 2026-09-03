namespace ISCM.Domain.Interfaces;

/// <summary>
/// Defines the scope boundary for evidence isolation.
/// Evidence must be scoped to prevent cross-contamination.
/// </summary>
public interface IEvidenceScope
{
    string ScanId { get; }
    string SubControlId { get; }
    string? PathId { get; }

    bool IsInScope(string scanId, string subControlId, string? pathId);
    void ValidateScope();
}