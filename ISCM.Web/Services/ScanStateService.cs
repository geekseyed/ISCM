using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Diagnostics;

namespace ISCM.Web.Services;

// EDIT: این کلاس قلب تپنده UI است و وضعیت اسکن را بین تمام تب‌ها به اشتراک می‌گذارد.
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
    // EDIT: طبق قانون «زبان تماماً انگلیسی»، مقدار پیش‌فرض فارسی حذف شد.
    public string SelectedSystem { get; set; } = "Shift Expert System";
    public string HostnameContext => $"{SelectedZone} / {SelectedSystem}";

    public List<string> EventLog { get; set; } = new();
    public List<string> ConsoleLogs { get; set; } = new();

    public string ScanDuration { get; set; } = "—";
    public int TotalChecks { get; set; } = 0;
    public string ConsoleStatusText { get; set; } = "Ready to scan";
    public string ConsoleStatusClass { get; set; } = "";

    // EDIT: ردیف SCAN TIME در داشبورد — قبل از اسکن مقدار Placeholder نمایش داده می‌شود.
    public string ScanTimeText { get; private set; } = "Not scanned yet";

    // ─────────────────────────────────────────────────────────────
    // EDIT: قابلیت ویرایش دستی اطلاعات سیستم (دکمه Edit در داشبورد)
    // ─────────────────────────────────────────────────────────────
    public bool IsEditingSystemInfo { get; private set; }

    // EDIT: مقادیر پیش‌نویس که به Inputها Bind می‌شوند.
    public string DraftHostname { get; set; } = "";
    public string DraftIpAddress { get; set; } = "";
    public string DraftOsVersion { get; set; } = "";
    public string DraftOsBuild { get; set; } = "";

    // EDIT: مقادیر Override شده توسط کاربر (اولویت بالاتر از نتیجه اسکن).
    private string? _overrideHostname;
    private string? _overrideIpAddress;
    private string? _overrideOsVersion;
    private string? _overrideOsBuild;

    // EDIT: پراپرتی‌های Only-Read برای نمایش — اولویت: Override کاربر ← نتیجه اسکن ← Placeholder
    public string DisplayHostname => _overrideHostname ?? CurrentScanResult?.Hostname ?? "—";
    public string DisplayIpAddress => _overrideIpAddress ?? CurrentScanResult?.IpAddress ?? "—";
    public string DisplayOsVersion => _overrideOsVersion ?? CurrentScanResult?.OsVersion ?? "—";
    public string DisplayOsBuild => _overrideOsBuild ?? CurrentScanResult?.OsBuild ?? "—";

    // EDIT: شروع ویرایش — مقادیر فعلی در Draft کپی می‌شوند.
    public void StartEditingSystemInfo()
    {
        DraftHostname = DisplayHostname == "—" ? "" : DisplayHostname;
        DraftIpAddress = DisplayIpAddress == "—" ? "" : DisplayIpAddress;
        DraftOsVersion = DisplayOsVersion == "—" ? "" : DisplayOsVersion;
        DraftOsBuild = DisplayOsBuild == "—" ? "" : DisplayOsBuild;
        IsEditingSystemInfo = true;
        OnChange?.Invoke();
    }

    // EDIT: ذخیره ویرایش — مقادیر Draft به Override منتقل می‌شوند.
    public void SaveSystemInfoEdits()
    {
        _overrideHostname = string.IsNullOrWhiteSpace(DraftHostname) ? null : DraftHostname.Trim();
        _overrideIpAddress = string.IsNullOrWhiteSpace(DraftIpAddress) ? null : DraftIpAddress.Trim();
        _overrideOsVersion = string.IsNullOrWhiteSpace(DraftOsVersion) ? null : DraftOsVersion.Trim();
        _overrideOsBuild = string.IsNullOrWhiteSpace(DraftOsBuild) ? null : DraftOsBuild.Trim();
        IsEditingSystemInfo = false;
        LogAction("System information manually edited by user.");
    }

    // EDIT: انصراف از ویرایش بدون ذخیره.
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
                OnChange?.Invoke();
            });

            var scanResult = await _scanService.RunScanAsync(ScanMode.Full, progress);

            stopwatch.Stop();

            CurrentScanResult = scanResult;
            _historyService.AddScan(scanResult);

            ScanDuration = $"{stopwatch.Elapsed.TotalSeconds:F1}s";
            TotalChecks = scanResult.Findings.Count;
            ConsoleStatusText = "Scan Complete";
            ConsoleStatusClass = "complete";

            // EDIT: ثبت زمان پایان اسکن برای ردیف SCAN TIME (فرمت مطابق طرح: 2026-08-15 08:42)
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