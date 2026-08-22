using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents a parent control from the hardening baseline (PDF 17-item structure).
/// Backend may have 22+ technical checks, but UI displays 17 parent controls.
/// </summary>
public class ControlDefinition
{
    public string ControlId { get; set; } = string.Empty; // "01", "02", etc.
    public string BaselineId { get; set; } = string.Empty; // "MNDCHI-01"
    public string Title { get; set; } = string.Empty; // Exact name from PDF
    public string Description { get; set; } = string.Empty;
    public CheckCategory Category { get; set; }
    public CheckSeverity Severity { get; set; }
    public bool IsBaseline { get; set; } = true;
    public List<string> TechnicalCheckIds { get; set; } = new();

    /// <summary>
    /// Calculate parent status from child findings.
    /// - If any finding is FAIL → Parent = FAIL
    /// - If any finding is ERROR → Parent = UNKNOWN (not FAIL)
    /// - If all findings are PASS → Parent = PASS
    /// - If no findings → Parent = UNKNOWN
    /// </summary>
    public CheckStatus CalculateParentStatus(IEnumerable<Finding> findings)
    {
        var findingsList = findings.ToList();

        // No findings = UNKNOWN (evidence unavailable)
        if (!findingsList.Any()) return CheckStatus.Unknown;

        // If any finding has ERROR status → UNKNOWN (not FAIL)
        if (findingsList.Any(f => f.Status == CheckStatus.Error))
        {
            return CheckStatus.Unknown;
        }

        // If any finding is FAIL → Parent = FAIL
        if (findingsList.Any(f => f.Status == CheckStatus.Fail))
        {
            return CheckStatus.Fail;
        }

        // If any finding is WARNING → Parent = FAIL (warning = partial failure)
        if (findingsList.Any(f => f.Status == CheckStatus.Warning))
        {
            return CheckStatus.Fail;
        }

        // If all findings are PASS → Parent = PASS
        if (findingsList.All(f => f.Status == CheckStatus.Pass))
        {
            return CheckStatus.Pass;
        }

        // Fallback: UNKNOWN
        return CheckStatus.Unknown;
    }
}