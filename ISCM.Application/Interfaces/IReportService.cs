using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IReportService
{
    Task<string> GenerateAndSaveReportAsync(ScanResult scanResult, string outputDirectory);
    Task<string> GenerateAndSaveJsonReportAsync(ScanResult scanResult, string outputDirectory);

    // متد جدید برای خروجی CSV
    Task<string> GenerateAndSaveCsvReportAsync(ScanResult scanResult, string outputDirectory);
}