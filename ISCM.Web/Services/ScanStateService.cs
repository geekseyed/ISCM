using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

public class ScanStateService
{
    public ScanResult? CurrentScanResult { get; set; }
    public bool IsScanning { get; set; } = false;
    public event Action? OnChange;

    // مدیریت Zone و System
    public string SelectedZone { get; set; } = "ERDC";
    public string SelectedSystem { get; set; } = "سیستم کارشناس شیفت";
    public string HostnameContext => $"{SelectedZone} / {SelectedSystem}";

    // لاگ ریز فعالیت‌ها (Event Log)
    public List<string> EventLog { get; set; } = new();

    public void LogAction(string action)
    {
        EventLog.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {action}");
        OnChange?.Invoke();
    }

    public void SetScanResult(ScanResult result)
    {
        CurrentScanResult = result;
        OnChange?.Invoke();
    }
}