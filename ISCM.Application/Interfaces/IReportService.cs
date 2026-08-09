using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;
public interface IReportService
{
    // متد تولید گزارش HTML
    Task<string> GenerateAndSaveReportAsync(ScanResult scanResult, string outputDirectory);

    // متد جدید: تولید گزارش JSON
    Task<string> GenerateAndSaveJsonReportAsync(ScanResult scanResult, string outputDirectory);
}
