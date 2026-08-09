using System.IO;
using System.Text;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using System.Text.Json;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;




namespace ISCM.Infrastructure.Reporting;

public class HtmlReportGenerator : IReportService
{
    public async Task<string> GenerateAndSaveReportAsync(ScanResult scanResult, string outputDirectory)
    {
        // ۱. ساخت نام فایل بر اساس نام سیستم و زمان
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string safeHostname = string.IsNullOrWhiteSpace(scanResult.Hostname) ? "UnknownHost" : scanResult.Hostname;
        string fileName = $"DefenDoor_Report_{safeHostname}_{timestamp}.html";

        // ۲. ترکیب مسیر پوشه با نام فایل
        Directory.CreateDirectory(outputDirectory);
        string filePath = Path.Combine(outputDirectory, fileName);

        // ۳. ساخت محتوای HTML (با استفاده از $$ برای جلوگیری از تداخل با CSS)
        string htmlContent = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>DefenDoor Scan Report - {{scanResult.Hostname}}</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #f4f7f6; padding: 20px; }
                    .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
                    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                    .info { margin-bottom: 20px; font-size: 16px; }
                    .info span { font-weight: bold; color: #2c3e50; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th { background: #34495e; color: white; padding: 10px; text-align: left; }
                    td { padding: 10px; border-bottom: 1px solid #ddd; }
                    .pass { color: #27ae60; font-weight: bold; }
                    .fail { color: #e74c3c; font-weight: bold; }
                    .error { color: #f39c12; font-weight: bold; }
                    .ignored { color: #7f8c8d; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>DefenDoor Security Compliance Report</h1>
                    <div class="info"><span>Hostname:</span> {{scanResult.Hostname}}</div>
                    <div class="info"><span>IP Address:</span> {{scanResult.IpAddress}}</div>
                    <div class="info"><span>OS Version:</span> {{scanResult.OsVersion}}</div>
                    <div class="info"><span>Scan Date:</span> {{scanResult.StartedAtUtc.LocalDateTime}}</div>
                    <div class="info"><span>Compliance Score:</span> {{scanResult.ComplianceScore}}% (Grade: {{scanResult.Grade}})</div>

                    <h2>Findings</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Check ID</th>
                                <th>Name</th>
                                <th>Current Value</th>
                                <th>Expected Value</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
            """;

        // ۴. اضافه کردن تک‌تک نتایج به جدول HTML
        foreach (var finding in scanResult.Findings)
        {
            string cssClass = finding.Status.ToString().ToLower();
            htmlContent += $$"""
                            <tr>
                                <td>{{finding.CheckId}}</td>
                                <td>{{finding.Name}}</td>
                                <td>{{finding.CurrentValue}}</td>
                                <td>{{finding.ExpectedValue}}</td>
                                <td class="{{cssClass}}">{{finding.Status}}</td>
                            </tr>
            """;
        }

        htmlContent += """
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            """;

        // ۵. ذخیره فایل روی دیسک
        await File.WriteAllTextAsync(filePath, htmlContent, Encoding.UTF8);

        // ۶. برگرداندن مسیر فایل
        return filePath;
    }

    // ---------------------------------------------------------
    // متد جدید: تولید گزارش JSON
    // ---------------------------------------------------------
    public async Task<string> GenerateAndSaveJsonReportAsync(ScanResult scanResult, string outputDirectory)
    {
        // ۱. ساخت نام فایل بر اساس نام سیستم و زمان
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string safeHostname = string.IsNullOrWhiteSpace(scanResult.Hostname) ? "UnknownHost" : scanResult.Hostname;
        string fileName = $"DefenDoor_Report_{safeHostname}_{timestamp}.json";

        // ۲. ترکیب مسیر پوشه با نام فایل
        Directory.CreateDirectory(outputDirectory);
        string filePath = Path.Combine(outputDirectory, fileName);

        // ۳. تنظیمات JSON برای خروجی خوانا و بدون بهم ریختگی کلمات فارسی
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        // ۴. ساخت یک آبجکت ناشناس (Anonymous Object) برای خروجی تمیز JSON
        var reportData = new
        {
            Hostname = scanResult.Hostname,
            IpAddress = scanResult.IpAddress,
            OsVersion = scanResult.OsVersion,
            ScanDate = scanResult.StartedAtUtc.LocalDateTime,
            ComplianceScore = scanResult.ComplianceScore,
            Grade = scanResult.Grade,
            Findings = scanResult.Findings.Select(f => new
            {
                f.CheckId,
                f.Name,
                Category = f.Category.ToString(),
                Severity = f.Severity.ToString(),
                Status = f.Status.ToString(),
                f.CurrentValue,
                f.ExpectedValue
            })
        };

        // ۵. تبدیل داده‌ها به فرمت JSON
        string jsonString = JsonSerializer.Serialize(reportData, jsonOptions);

        // ۶. ذخیره فایل روی دیسک
        await File.WriteAllTextAsync(filePath, jsonString, Encoding.UTF8);

        // ۷. برگرداندن مسیر فایل
        return filePath;
    }
}