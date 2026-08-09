using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

// مدل داده‌ای برای هر رکورد تاریخچه
public class ScanHistoryEntry
{
    public DateTime ScanTime { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public int ComplianceScore { get; set; }
    public string Grade { get; set; } = string.Empty;
}

// سرویس مدیریت تاریخچه
public class ScanHistoryService
{
    private readonly List<ScanHistoryEntry> _history = new();

    // readonly لیست برای نمایش به UI
    public IReadOnlyList<ScanHistoryEntry> History => _history.AsReadOnly();

    // متد افزودن یک اسکن جدید به تاریخچه
    public void AddScan(ScanResult result)
    {
        _history.Insert(0, new ScanHistoryEntry // Insert(0) یعنی جدیدترین در بالای لیست قرار بگیرد
        {
            ScanTime = DateTime.Now,
            Hostname = result.Hostname,
            ComplianceScore = result.ComplianceScore,
            Grade = result.Grade
        });
    }
}