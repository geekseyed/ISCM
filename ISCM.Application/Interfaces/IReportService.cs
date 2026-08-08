using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IReportService
{
    // این متد مسیر فایل ذخیره شده را برمی‌گرداند
    Task<string> GenerateAndSaveReportAsync(ScanResult scanResult, string outputDirectory);
}
