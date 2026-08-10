using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Globalization;

namespace ISCM.Web.Services;

public class ScanStateService
{
    private readonly IScanService _scanService;
    private readonly ScanHistoryService _historyService;

    public ScanStateService(IScanService scanService, ScanHistoryService historyService)
    {
        _scanService = scanService;
        _historyService = historyService;
    }

    public ScanResult? CurrentScanResult { get; set; }
    public bool IsScanning { get; set; } = false;
    public event Action? OnChange;

    public string SelectedZone { get; set; } = "ERDC";
    public string SelectedSystem { get; set; } = "سیستم کارشناس شیفت";
    public string HostnameContext => $"{SelectedZone} / {SelectedSystem}";

    public List<string> EventLog { get; set; } = new();
    public List<string> ConsoleLogs { get; set; } = new();

    // مدیریت تاریخ
    public string ShamsiDate { get; set; } = "";
    public string GregorianDate { get; set; } = "";

    public void InitializeDates()
    {
        var pc = new PersianCalendar();
        var now = DateTime.Now;
        ShamsiDate = $"{pc.GetYear(now)}/{pc.GetMonth(now):00}/{pc.GetDayOfMonth(now):00}";
        GregorianDate = now.ToString("yyyy/MM/dd");
    }

    public void UpdateShamsiDate(string newDate)
    {
        if (newDate != ShamsiDate)
        {
            LogAction($"Scan Date changed from {ShamsiDate} to {newDate}");
            ShamsiDate = newDate;
            try
            {
                var parts = newDate.Split('/');
                if (parts.Length == 3 && int.TryParse(parts[0], out int y) && int.TryParse(parts[1], out int m) && int.TryParse(parts[2], out int d))
                {
                    var pc = new PersianCalendar();
                    var gDate = pc.ToDateTime(y, m, d, 0, 0, 0, 0);
                    GregorianDate = gDate.ToString("yyyy/MM/dd");
                }
            }
            catch { }
            OnChange?.Invoke();
        }
    }

    public void LogAction(string action)
    {
        EventLog.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {action}");
        OnChange?.Invoke();
    }

    public async Task ExecuteScanAsync()
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            ConsoleLogs.Clear();
            LogAction($"Scan started for {HostnameContext}");
            OnChange?.Invoke();

            var progress = new Progress<string>(status =>
            {
                ConsoleLogs.Add($"[{DateTime.Now:HH:mm:ss}] {status}");
                OnChange?.Invoke();
            });

            var scanResult = await _scanService.RunScanAsync(ScanMode.Full, progress);
            CurrentScanResult = scanResult;
            _historyService.AddScan(scanResult);
            LogAction($"Scan completed. Score: {scanResult.ComplianceScore}%");
        }
        catch (Exception ex)
        {
            LogAction($"Error during scan: {ex.Message}");
        }
        finally
        {
            IsScanning = false;
            OnChange?.Invoke();
        }
    }
}