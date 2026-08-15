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

    // EDIT (مرحله ب): لیست سفید ابزارهای رفع مشکل — فقط این اجراها مجازند (امنیتی)
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

    // EDIT (مرحله ب): اجرای امن ابزار رفع مشکل روی همین میزبان (UseShellExecute + لیست سفید)
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

    // EDIT (مرحله ب): اسکن مجددِ یک چک و جایگزینی نتیجه در CurrentScanResult
    public async Task RescanSingleCheckAsync(string checkId)
    {
        if (CurrentScanResult == null || IsScanning) return;

        try
        {
            var newFinding = await _scanService.RescanCheckAsync(checkId);
            CurrentScanResult.ReplaceFinding(newFinding);
            LogAction($"User rescanned {checkId} => {newFinding.Status}");
        }
        catch (Exception ex)
        {
            LogAction($"Rescan failed for {checkId}: {ex.Message}");
        }
    }

    public async Task ExecuteScanAsync()
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            ConsoleLogs.Clear();

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