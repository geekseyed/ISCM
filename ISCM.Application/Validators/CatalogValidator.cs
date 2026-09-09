using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Validators;

public class CatalogValidator : ICatalogValidator
{
    public CatalogValidationResult ValidateCatalog()
    {
        var result = new CatalogValidationResult();

        result.Issues.AddRange(FindDuplicateParentIds());
        result.Issues.AddRange(FindDuplicateSubControlIds());
        result.Issues.AddRange(FindOrphanSubControls());
        result.Issues.AddRange(FindMissingTechnicalCheckMappings());
        result.Issues.AddRange(FindInvalidEvidenceSources());
        result.Issues.AddRange(FindInvalidValueTypeOperatorCombinations());
        result.Issues.AddRange(FindMissingTypedContract()); // Phase 10.2.3

        result.IsValid = !result.Issues.Any(i => i.Severity == "Critical");

        return result;
    }

    public List<CatalogIntegrityIssue> FindDuplicateParentIds()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var controls = ControlCatalog.GetAll();

        var duplicates = controls
            .GroupBy(c => c.ControlId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        foreach (var id in duplicates)
        {
            issues.Add(new CatalogIntegrityIssue
            {
                IssueId = $"DUP-PARENT-{id}",
                Severity = "Critical",
                Category = "DuplicateParentId",
                Description = $"Duplicate ParentControlId: {id}",
                AffectedParentControlId = id
            });
        }

        return issues;
    }

    public List<CatalogIntegrityIssue> FindDuplicateSubControlIds()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var allSubControls = GetAllSubControls();

        var duplicates = allSubControls
            .GroupBy(s => s.SubControlId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        foreach (var id in duplicates)
        {
            issues.Add(new CatalogIntegrityIssue
            {
                IssueId = $"DUP-SUB-{id}",
                Severity = "Critical",
                Category = "DuplicateSubControlId",
                Description = $"Duplicate SubControlId: {id}",
                AffectedSubControlId = id
            });
        }

        return issues;
    }

    public List<CatalogIntegrityIssue> FindOrphanSubControls()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var allSubControls = GetAllSubControls();
        var parentIds = ControlCatalog.GetAll().Select(c => c.ControlId).ToHashSet();

        foreach (var sub in allSubControls)
        {
            if (!parentIds.Contains(sub.ParentControlId))
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"ORPHAN-{sub.SubControlId}",
                    Severity = "Critical",
                    Category = "OrphanSubControl",
                    Description = $"SubControl {sub.SubControlId} references non-existent ParentControlId: {sub.ParentControlId}",
                    AffectedSubControlId = sub.SubControlId,
                    AffectedParentControlId = sub.ParentControlId
                });
            }
        }

        return issues;
    }

    public List<CatalogIntegrityIssue> FindMissingTechnicalCheckMappings()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var controls = ControlCatalog.GetAll();

        foreach (var control in controls)
        {
            if (control.TechnicalCheckIds == null || !control.TechnicalCheckIds.Any())
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"NO-TECH-{control.ControlId}",
                    Severity = "High",
                    Category = "MissingTechnicalCheckMapping",
                    Description = $"Control {control.ControlId} has no TechnicalCheckIds defined",
                    AffectedParentControlId = control.ControlId
                });
            }
        }

        return issues;
    }

    public List<CatalogIntegrityIssue> FindInvalidEvidenceSources()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var allSubControls = GetAllSubControls();

        foreach (var sub in allSubControls)
        {
            if (sub.EvidenceSources == null || !sub.EvidenceSources.Any())
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"NO-EVIDENCE-{sub.SubControlId}",
                    Severity = "High",
                    Category = "MissingEvidenceSource",
                    Description = $"SubControl {sub.SubControlId} has no EvidenceSource defined",
                    AffectedSubControlId = sub.SubControlId
                });
            }
        }

        return issues;
    }

    public List<CatalogIntegrityIssue> FindInvalidValueTypeOperatorCombinations()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var allSubControls = GetAllSubControls();

        foreach (var sub in allSubControls)
        {
            var isValid = IsValidValueTypeOperatorCombination(sub.ExpectedValueType, sub.Operator);
            if (!isValid)
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"INVALID-COMBO-{sub.SubControlId}",
                    Severity = "High",
                    Category = "InvalidValueTypeOperator",
                    Description = $"SubControl {sub.SubControlId} has invalid ValueType/Operator combination: {sub.ExpectedValueType}/{sub.Operator}",
                    AffectedSubControlId = sub.SubControlId
                });
            }
        }

        return issues;
    }

    /// <summary>
    /// Phase 10.2.3: Ensures all required SubControls with ExpectedValue
    /// have a meaningful ExpectedValueType (not just defaulting to String).
    /// 
    /// This prevents future SubControls from being added without proper
    /// typed-pipeline metadata.
    /// </summary>
    public List<CatalogIntegrityIssue> FindMissingTypedContract()
    {
        var issues = new List<CatalogIntegrityIssue>();
        var allSubControls = GetAllSubControls();

        // Exemptions for SubControls whose ExpectedValue genuinely needs String type
        var stringExemptions = new HashSet<string>
        {
            "GUEST-001.2",  // "Unique complex name" — genuinely a string
            "SEC-001.8",    // "Set to a unique non-obvious name" — genuinely a string
            "SMB-001.1",    // PowerShell command string
            "WUP-001.2"     // WSUS URL string
        };

        foreach (var sub in allSubControls)
        {
            // Only check required SubControls with non-empty ExpectedValue
            if (!sub.IsRequired || string.IsNullOrWhiteSpace(sub.ExpectedValue))
                continue;

            // Skip exempted SubControls
            if (stringExemptions.Contains(sub.SubControlId))
                continue;

            // Check if ExpectedValueType is still the default (String)
            // when it should be something more specific
            if (sub.ExpectedValueType == ExpectedValueType.String)
            {
                // Heuristic: if ExpectedValue contains numeric patterns,
                // it should probably be Integer or Duration
                if (ContainsNumericPattern(sub.ExpectedValue))
                {
                    issues.Add(new CatalogIntegrityIssue
                    {
                        IssueId = $"MISSING-TYPE-{sub.SubControlId}",
                        Severity = "High",
                        Category = "MissingTypedContract",
                        Description = $"SubControl {sub.SubControlId} has numeric ExpectedValue '{sub.ExpectedValue}' but ExpectedValueType is String (should be Integer/Duration)",
                        AffectedSubControlId = sub.SubControlId
                    });
                }
                // If ExpectedValue contains boolean keywords, it should be Boolean
                else if (ContainsBooleanPattern(sub.ExpectedValue))
                {
                    issues.Add(new CatalogIntegrityIssue
                    {
                        IssueId = $"MISSING-TYPE-{sub.SubControlId}",
                        Severity = "High",
                        Category = "MissingTypedContract",
                        Description = $"SubControl {sub.SubControlId} has boolean ExpectedValue '{sub.ExpectedValue}' but ExpectedValueType is String (should be Boolean)",
                        AffectedSubControlId = sub.SubControlId
                    });
                }
            }
        }

        return issues;
    }

    private bool ContainsNumericPattern(string value)
    {
        var numericPatterns = new[] { "characters", "KB", "MB", "passwords remembered", "attempts", "seconds", "minutes", "days" };
        return numericPatterns.Any(p => value.Contains(p, StringComparison.OrdinalIgnoreCase)) &&
               System.Text.RegularExpressions.Regex.IsMatch(value, @"\d");
    }

    private bool ContainsBooleanPattern(string value)
    {
        var booleanPatterns = new[] { "Enabled", "Disabled", "On", "Off", "Yes", "No" };
        return booleanPatterns.Any(p =>
            System.Text.RegularExpressions.Regex.IsMatch(value, $@"\b{p}\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
    }

    private bool IsValidValueTypeOperatorCombination(ExpectedValueType valueType, Operator op)
    {
        return valueType switch
        {
            ExpectedValueType.Integer => op is Operator.Equals or Operator.NotEquals or Operator.GreaterThan
                or Operator.GreaterOrEqual or Operator.LessThan or Operator.LessOrEqual,
            ExpectedValueType.Duration => op is Operator.Equals or Operator.NotEquals or Operator.GreaterThan
                or Operator.GreaterOrEqual or Operator.LessThan or Operator.LessOrEqual,
            ExpectedValueType.Boolean => op is Operator.Equals or Operator.NotEquals,
            ExpectedValueType.String => op is Operator.Equals or Operator.NotEquals or Operator.Contains,
            ExpectedValueType.Enum => op is Operator.Equals or Operator.NotEquals or Operator.SetMembership,
            ExpectedValueType.RegistryValue => op is Operator.Equals or Operator.NotEquals,
            ExpectedValueType.PolicyValue => op is Operator.Equals or Operator.NotEquals,
            ExpectedValueType.Collection => op is Operator.Contains or Operator.SetMembership,
            _ => true
        };
    }

    private List<SubControlDefinition> GetAllSubControls()
    {
        var allSubControls = new List<SubControlDefinition>();
        foreach (var control in ControlCatalog.GetAll())
        {
            if (control.SubControls != null)
            {
                allSubControls.AddRange(control.SubControls);
            }
        }
        return allSubControls;
    }
}