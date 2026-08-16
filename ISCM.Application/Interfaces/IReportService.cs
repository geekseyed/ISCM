using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IReportService
{
    Task<string> GenerateAndSaveReportAsync(ScanResult scanResult, string outputDir, string baseFileName);
    Task<string> GenerateAndSaveJsonReportAsync(ScanResult scanResult, string outputDir, string baseFileName);
    Task<string> GenerateAndSaveCsvReportAsync(ScanResult scanResult, string outputDir, string baseFileName);
}