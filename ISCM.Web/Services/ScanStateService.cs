using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

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
    public string SelectedSystem { get; set; } = "Shift Expert System";
    public string HostnameContext => $"{SelectedZone} / {SelectedSystem}";

    public List<string> EventLog { get; set; } = new();
    public List<string> ConsoleLogs { get; set; } = new();

    public string ScanDuration { get; set; } = "—";
    public int TotalChecks { get; set; } = 0;
    public string ConsoleStatusText { get; set; } = "Ready to scan";
    public string ConsoleStatusClass { get; set; } = "";

    // EDIT: شمارنده زنده برای نمایش x/15 در ستون CHECKS حین اسکن
    public int CompletedChecks { get; private set; } = 0;
    public int ExpectedChecks { get; private set; } = 0;

    public string ScanTimeText { get; private set; } = "Not scanned yet";

    public bool IsEditingSystemInfo { get; private set; }
    public string DraftHostname { get; set; } = "";
    public string DraftIpAddress { get; set; } = "";
    public string DraftOsVersion { get; set; } = "";
    public string DraftOsBuild { get; set; } = "";

    private string? _overrideHostname;
    private string? _overrideIpAddress;
    private string? _overrideOsVersion;
    private string? _overrideOsBuild;

    public string DisplayHostname => _overrideHostname ?? CurrentScanResult?.Hostname ?? "—";
    public string DisplayIpAddress => _overrideIpAddress ?? CurrentScanResult?.IpAddress ?? "—";
    public string DisplayOsVersion => _overrideOsVersion ?? CurrentScanResult?.OsVersion ?? "—";
    public string DisplayOsBuild => _overrideOsBuild ?? CurrentScanResult?.OsBuild ?? "—";

    public void StartEditingSystemInfo()
    {
        DraftHostname = DisplayHostname == "—" ? "" : DisplayHostname;
        DraftIpAddress = DisplayIpAddress == "—" ? "" : DisplayIpAddress;
        DraftOsVersion = DisplayOsVersion == "—" ? "" : DisplayOsVersion;
        DraftOsBuild = DisplayOsBuild == "—" ? "" : DisplayOsBuild;
        IsEditingSystemInfo = true;
        OnChange?.Invoke();
    }

    public void SaveSystemInfoEdits()
    {
        _overrideHostname = string.IsNullOrWhiteSpace(DraftHostname) ? null : DraftHostname.Trim();
        _overrideIpAddress = string.IsNullOrWhiteSpace(DraftIpAddress) ? null : DraftIpAddress.Trim();
        _overrideOsVersion = string.IsNullOrWhiteSpace(DraftOsVersion) ? null : DraftOsVersion.Trim();
        _overrideOsBuild = string.IsNullOrWhiteSpace(DraftOsBuild) ? null : DraftOsBuild.Trim();
        IsEditingSystemInfo = false;
        LogAction("System information manually edited by user.");
    }

    public void CancelSystemInfoEdits()
    {
        IsEditingSystemInfo = false;
        OnChange?.Invoke();
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

            // EDIT: بازنشانی و مقداردهی شمارنده زنده از طریق قرارداد IScanService
            CompletedChecks = 0;
            ExpectedChecks = _scanService.TotalCheckCount;

            ConsoleStatusText = "Scanning...";
            ConsoleStatusClass = "scanning";
            ScanDuration = "...";
            TotalChecks = 0;

            LogAction($"Scan started for {HostnameContext}");
            OnChange?.Invoke();

            var stopwatch = Stopwatch.StartNew();

            var progress = new Progress<string>(status =>
            {
                ConsoleLogs.Add($"[{DateTime.Now:HH:mm:ss}] {status}");

                // EDIT: هر خط نتیجه (PASS/FAIL/WARN/ERROR) یعنی یک چک کامل‌شده
                if (status.StartsWith("[PASS]") || status.StartsWith("[FAIL]") ||
                    status.StartsWith("[WARN]") || status.StartsWith("[ERROR]"))
                {
                    CompletedChecks++;
                }
                OnChange?.Invoke();
            });

            var scanResult = await _scanService.RunScanAsync(ScanMode.Full, progress);

            stopwatch.Stop();

            CurrentScanResult = scanResult;
            _historyService.AddScan(scanResult);

            ScanDuration = $"{stopwatch.Elapsed.TotalSeconds:F1}s";
            TotalChecks = scanResult.Findings.Count;

            // EDIT: متن وضعیت پایانی مطابق طرح: Scan Complete - 15/15 checks
            ConsoleStatusText = $"Scan Complete - {scanResult.Findings.Count}/{scanResult.Findings.Count} checks";
            ConsoleStatusClass = "complete";

            ScanTimeText = DateTime.Now.ToString("yyyy-MM-dd HH:mm");

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