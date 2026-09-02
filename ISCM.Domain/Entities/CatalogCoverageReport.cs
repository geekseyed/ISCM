namespace ISCM.Domain.Entities;

public class CatalogCoverageReport
{
    public DateTime GeneratedAt { get; set; }
    public int TotalParentControls { get; set; }
    public int TotalSubControls { get; set; }
    public int BaselineSubControls { get; set; }
    public int ExtendedSubControls { get; set; }
    public List<CatalogIntegrityIssue> Issues { get; set; } = new();
    public List<SubControlCoverageEntry> CoverageEntries { get; set; } = new();
}

public class SubControlCoverageEntry
{
    public string SubControlId { get; set; }
    public string ParentControlId { get; set; }
    public bool HasTechnicalCheckMapping { get; set; }
    public bool HasCheckImplementation { get; set; }
    public bool HasEvidenceSource { get; set; }
    public bool HasParser { get; set; }
    public bool HasNormalizer { get; set; }
    public bool HasEvaluator { get; set; }
    public bool HasRemediation { get; set; }
    public int DefinedPathCount { get; set; }
    public int RequiredPathCount { get; set; }
    public string CoverageStatus { get; set; }
}

public class CatalogIntegrityIssue
{
    public string IssueId { get; set; }
    public string Severity { get; set; }
    public string Category { get; set; }
    public string Description { get; set; }
    public string? AffectedSubControlId { get; set; }
    public string? AffectedParentControlId { get; set; }
}