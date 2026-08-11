using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using System.Diagnostics;
using ISCM.Domain.Enums;

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

    // متغیرهای جدید برای نوار خلاصه
    public string ScanDuration { get; set; } = "—";
    public int TotalChecks { get; set; } = 0;
    public string ConsoleStatusText { get; set; } = "Ready to scan";
    public string ConsoleStatusClass { get; set; } = "";

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

            // تنظیم وضعیت روی "در حال اسکن"
            ConsoleStatusText = "Scanning...";
            ConsoleStatusClass = "scanning";
            ScanDuration = "...";
            TotalChecks = 0;

            LogAction($"Scan started for {HostnameContext}");
            OnChange?.Invoke();

            var stopwatch = Stopwatch.StartNew(); // شروع زمان‌سنج

            var progress = new Progress<string>(status =>
            {
                ConsoleLogs.Add($"[{DateTime.Now:HH:mm:ss}] {status}");
                OnChange?.Invoke();
            });

            var scanResult = await _scanService.RunScanAsync(ScanMode.Full, progress);

            stopwatch.Stop(); // توقف زمان‌سنج

            CurrentScanResult = scanResult;
            _historyService.AddScan(scanResult);

            // ثبت مقادیر نهایی در نوار خلاصه
            ScanDuration = $"{stopwatch.Elapsed.TotalSeconds:F1}s";
            TotalChecks = scanResult.Findings.Count;
            ConsoleStatusText = "Scan Complete";
            ConsoleStatusClass = "complete";

            LogAction($"Scan completed. Score: {scanResult.ComplianceScore}%");
        }
        catch (Exception ex)
        {
            LogAction($"Error during scan: {ex.Message}");
            ConsoleStatusText = "Scan Failed";
            ConsoleStatusClass = "failed";
        }
        finally
        {
            IsScanning = false;
            OnChange?.Invoke();
        }
    }
}