using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface ICatalogCoverageService
{
    CatalogCoverageReport GenerateCoverageReport();
    List<CatalogIntegrityIssue> ValidateCatalogIntegrity();
}