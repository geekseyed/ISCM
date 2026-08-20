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

    // EDIT (گروه C): چراغ Connected همیشه فعال (نرم‌افزار محلی)
    public bool IsConnected { get; private set; } = true;

    // EDIT (گروه C): شمارنده‌های زنده — با هر اسکن/Rescan از صفر شروع می‌کنند
    public int LivePassCount { get; private set; } = 0;
    public int LiveFailCount { get; private set; } = 0;
    public string LastCheckResult { get; private set; } = ""; // "pass" / "fail" / ""

    public string SelectedZone { get; set; } = "ERDC";
    public string SelectedSystem { get; set; } = "Shift Expert System";
    public string HostnameContext => $"{SelectedZone} / {SelectedSystem}";

    public List<string> EventLog { get; set; } = new();
    public List<string> ConsoleLogs { get; set; } = new();

    public string ScanDuration { get; set; } = "—";
    public int TotalChecks { get; set; } = 0;
    public string ConsoleStatusText { get; set; } = "Ready to scan";
    public string ConsoleStatusClass { get; set; } = "";

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

    private static readonly HashSet<string> AllowedTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "secpol.msc", "regedit.exe", "powershell.exe", "net.exe",
        "gpedit.msc", "lusrmgr.msc", "compmgmt.msc"
    };

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

    public void LaunchFixTool(string tool)
    {
        if (!AllowedTools.Contains(tool))
        {
            LogAction($"Blocked unknown tool: {tool}");
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(tool) { UseShellExecute = true });
            LogAction($"User launched fix tool: {tool}");
        }
        catch (Exception ex)
        {
            LogAction($"Failed to launch {tool}: {ex.Message}");
        }
    }

    // EDIT (گروه C): ریست شمارنده‌ها هنگام Rescan و ثبت نتیجهٔ همان یک چک
    public async Task RescanSingleCheckAsync(string checkId)
    {
        if (CurrentScanResult == null || IsScanning) return;

        try
        {
            // ریست شمارنده‌های زنده قبل از Rescan
            LivePassCount = 0;
            LiveFailCount = 0;
            LastCheckResult = "";
            CompletedChecks = 0;
            ExpectedChecks = 1; // فقط یک چک
            IsScanning = true;
            ConsoleStatusText = "Rescanning...";
            ConsoleStatusClass = "scanning";
            OnChange?.Invoke();

            var newFinding = await _scanService.RescanCheckAsync(checkId);
            CurrentScanResult.ReplaceFinding(newFinding);

            // ثبت نتیجه در شمارندهٔ زنده
            if (newFinding.Status == CheckStatus.Pass)
            {
                LivePassCount = 1;
                LastCheckResult = "pass";
            }
            else if (newFinding.Status == CheckStatus.Fail)
            {
                LiveFailCount = 1;
                LastCheckResult = "fail";
            }
            CompletedChecks = 1;

            ConsoleStatusText = $"Rescan complete - {newFinding.Status}";
            ConsoleStatusClass = "complete";
            LastCheckResult = "";
            LogAction($"User rescanned {checkId} => {newFinding.Status}");
        }
        catch (Exception ex)
        {
            LogAction($"Rescan failed for {checkId}: {ex.Message}");
            ConsoleStatusText = "Rescan Failed";
            ConsoleStatusClass = "failed";
        }
        finally
        {
            IsScanning = false;
            OnChange?.Invoke();
        }
    }

    // EDIT (گروه C): متد کمکی برای ثبت نتیجهٔ هر چک حین اسکن
    public void RecordLiveCheckResult(string statusToken)
    {
        if (statusToken.Contains("[PASS]"))
        {
            LivePassCount++;
            LastCheckResult = "pass";
        }
        else if (statusToken.Contains("[FAIL]") || statusToken.Contains("[ERROR]"))
        {
            LiveFailCount++;
            LastCheckResult = "fail";
        }
        CompletedChecks++;
        OnChange?.Invoke();
    }

    public async Task ExecuteScanAsync()
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            ConsoleLogs.Clear();

            // EDIT (گروه C): ریست شمارنده‌های زنده در شروع اسکن
            LivePassCount = 0;
            LiveFailCount = 0;
            LastCheckResult = "";

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

                // EDIT (گروه C): ثبت زنده برای هر چک کامل‌شده
                if (status.StartsWith("[PASS]") || status.StartsWith("[FAIL]") ||
                    status.StartsWith("[WARN]") || status.StartsWith("[ERROR]"))
                {
                    RecordLiveCheckResult(status);
                }
                else
                {
                    OnChange?.Invoke();
                }
            });

            var scanResult = await _scanService.RunScanAsync(ScanMode.Full, progress);

            stopwatch.Stop();

            CurrentScanResult = scanResult;
            _historyService.AddScan(scanResult);

            ScanDuration = $"{stopwatch.Elapsed.TotalSeconds:F1}s";
            TotalChecks = scanResult.Findings.Count;

            ConsoleStatusText = $"Scan Complete - {scanResult.Findings.Count}/{scanResult.Findings.Count} checks";
            ConsoleStatusClass = "complete";

            ScanTimeText = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            LastCheckResult = "";

            LogAction($"Scan completed. Score: {scanResult.ComplianceScore}%");
        }
        catch (Exception ex)
        {
            LogAction($"Error during scan: {ex.Message}");
            ConsoleStatusText = "Scan Failed";
            ConsoleStatusClass = "failed";
            IsConnected = false;
        }
        finally
        {
            IsScanning = false;
            OnChange?.Invoke();
        }
    }
}