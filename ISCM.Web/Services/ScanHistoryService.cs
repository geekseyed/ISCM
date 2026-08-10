using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

public class ScanHistoryEntry
{
    public DateTime ScanTime { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty; // اضافه شد
    public int ComplianceScore { get; set; }
    public string Grade { get; set; } = string.Empty;
}

public class ScanHistoryService
{
    private readonly List<ScanHistoryEntry> _history = new();
    public IReadOnlyList<ScanHistoryEntry> History => _history.AsReadOnly();

    public void AddScan(ScanResult result)
    {
        _history.Insert(0, new ScanHistoryEntry
        {
            ScanTime = DateTime.Now,
            Hostname = result.Hostname,
            OsVersion = result.OsVersion, // ذخیره سیستم‌عامل
            ComplianceScore = result.ComplianceScore,
            Grade = result.Grade
        });
    }

    // متد جدید برای پاک کردن تاریخچه
    public void ClearHistory()
    {
        _history.Clear();
    }
}