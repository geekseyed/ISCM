using ISCM.Domain.Entities;

namespace ISCM.Application.Validators;

public interface ICatalogValidator
{
    CatalogValidationResult ValidateCatalog();
    List<CatalogIntegrityIssue> FindDuplicateParentIds();
    List<CatalogIntegrityIssue> FindDuplicateSubControlIds();
    List<CatalogIntegrityIssue> FindOrphanSubControls();
    List<CatalogIntegrityIssue> FindMissingTechnicalCheckMappings();
    List<CatalogIntegrityIssue> FindInvalidEvidenceSources();
    List<CatalogIntegrityIssue> FindInvalidValueTypeOperatorCombinations();
}

public class CatalogValidationResult
{
    public bool IsValid { get; set; }
    public List<CatalogIntegrityIssue> Issues { get; set; } = new();
    public int TotalIssues => Issues.Count;
    public int CriticalIssues => Issues.Count(i => i.Severity == "Critical");
    public int HighIssues => Issues.Count(i => i.Severity == "High");
}