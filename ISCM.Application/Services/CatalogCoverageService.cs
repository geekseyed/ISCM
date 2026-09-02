using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class CatalogCoverageService : ICatalogCoverageService
{
    public CatalogCoverageReport GenerateCoverageReport()
    {
        var report = new CatalogCoverageReport
        {
            GeneratedAt = DateTime.UtcNow
        };

        var controls = ControlCatalog.GetAll();
        var allSubControls = new List<SubControlDefinition>();

        foreach (var control in controls)
        {
            if (control.SubControls != null)
            {
                allSubControls.AddRange(control.SubControls);
            }
        }

        report.TotalParentControls = controls.Count();
        report.TotalSubControls = allSubControls.Count;
        report.BaselineSubControls = controls.Where(c => c.IsBaseline).Sum(c => c.SubControls?.Count ?? 0);
        report.ExtendedSubControls = controls.Where(c => !c.IsBaseline).Sum(c => c.SubControls?.Count ?? 0);

        foreach (var subControl in allSubControls)
        {
            var entry = new SubControlCoverageEntry
            {
                SubControlId = subControl.SubControlId,
                ParentControlId = subControl.ParentControlId,
                HasEvidenceSource = subControl.EvidenceSources != null && subControl.EvidenceSources.Any(),
                RequiredPathCount = subControl.RequiredPathCount,
                DefinedPathCount = 1,
                CoverageStatus = DetermineCoverageStatus(subControl)
            };
            report.CoverageEntries.Add(entry);
        }

        report.Issues = ValidateCatalogIntegrity();

        return report;
    }

    public List<CatalogIntegrityIssue> ValidateCatalogIntegrity()
    {
        var issues = new List<CatalogIntegrityIssue>();

        var controls = ControlCatalog.GetAll();
        var allSubControls = new List<SubControlDefinition>();

        foreach (var control in controls)
        {
            if (control.SubControls != null)
            {
                allSubControls.AddRange(control.SubControls);
            }
        }

        var duplicateIds = allSubControls
            .GroupBy(s => s.SubControlId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        foreach (var id in duplicateIds)
        {
            issues.Add(new CatalogIntegrityIssue
            {
                IssueId = $"DUP-SUB-{id}",
                Severity = "Critical",
                Category = "DuplicateId",
                Description = $"Duplicate SubControlId: {id}",
                AffectedSubControlId = id
            });
        }

        var parentIds = controls.Select(c => c.ControlId).ToHashSet();
        foreach (var sub in allSubControls)
        {
            if (!parentIds.Contains(sub.ParentControlId))
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"ORPHAN-{sub.SubControlId}",
                    Severity = "Critical",
                    Category = "OrphanSubControl",
                    Description = $"SubControl {sub.SubControlId} has invalid ParentControlId: {sub.ParentControlId}",
                    AffectedSubControlId = sub.SubControlId,
                    AffectedParentControlId = sub.ParentControlId
                });
            }
        }

        foreach (var control in controls.Where(c => !c.IsBaseline))
        {
            if (control.SubControls == null || !control.SubControls.Any())
            {
                issues.Add(new CatalogIntegrityIssue
                {
                    IssueId = $"EMPTY-EXT-{control.ControlId}",
                    Severity = "High",
                    Category = "EmptyExtendedControl",
                    Description = $"Extended control {control.ControlId} has no SubControls defined",
                    AffectedParentControlId = control.ControlId
                });
            }
        }

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

    private string DetermineCoverageStatus(SubControlDefinition subControl)
    {
        if (subControl.EvidenceSources == null || !subControl.EvidenceSources.Any())
            return "NOT_IMPLEMENTED";

        return "PARTIAL";
    }
}