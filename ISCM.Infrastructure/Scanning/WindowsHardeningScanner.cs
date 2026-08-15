using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Collectors;

namespace ISCM.Infrastructure.Scanning;

public class WindowsHardeningScanner : IScanService
{
    private readonly WindowsSystemInfoCollector _systemInfoCollector;
    private readonly IEnumerable<IHardeningCheck> _checks;

    public WindowsHardeningScanner(WindowsSystemInfoCollector systemInfoCollector, IEnumerable<IHardeningCheck> checks)
    {
        _systemInfoCollector = systemInfoCollector;
        _checks = checks;
    }

    // EDIT: پیاده‌سازی پراپرتی جدید قرارداد
    public int TotalCheckCount => _checks.Count();

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null)
    {
        progress?.Report("[INFO] DefenDoor Scanner initialized");
        await Task.Delay(500);

        // EDIT: خط baseline همراه با تعداد قوانین (مطابق ویدیوی طرح)
        progress?.Report($"[INFO] Loading baseline: windows11-pro-hardening.json ({TotalCheckCount} rules)");
        await Task.Delay(300);

        var (hostname, ipAddress, macAddress, osVersion, osBuild) = _systemInfoCollector.Collect();
        var scanResult = new ScanResult(hostname, ipAddress, macAddress, osVersion, osBuild, mode);

        progress?.Report($"[INFO] Collecting system info... Hostname: {hostname}, IP: {ipAddress}");
        progress?.Report("[INFO] Collector: RegistryReader - reading HKLM policies...");
        await Task.Delay(500);

        foreach (var check in _checks)
        {
            await Task.Delay(1000);

            try
            {
                var finding = await check.EvaluateAsync();
                scanResult.AddFinding(finding);

                // EDIT: خط نتیجه رنگی، دقیقاً مطابق فرمت ویدیوی طرح
                progress?.Report(BuildResultLine(finding));
            }
            catch (Exception ex)
            {
                var errorFinding = new Finding(
                    check.CheckId,
                    "Unknown Check",
                    CheckCategory.System,
                    CheckSeverity.High,
                    CheckStatus.Error,
                    "Crash",
                    "N/A",
                    "The check failed to execute.",
                    ex.Message);
                scanResult.AddFinding(errorFinding);
                progress?.Report($"[ERROR] {check.CheckId}: {check.Name} = Crash ({ex.Message})");
            }
        }

        progress?.Report("[INFO] Finalizing scan and calculating compliance score...");
        await Task.Delay(500);

        scanResult.CompleteScan();
        return scanResult;
    }

    // EDIT: ساخت خط نتیجه با Switch Expression (یک ویژگی مدرن C#):
    // [PASS] FW-001: Firewall Domain Profile = Enabled (PASS)
    // [FAIL] SMB-001: SMBv1 Protocol = Enabled (FAIL - expected Disabled)
    // [WARN] PWD-001: Password Length = 8 (WARN - expected 14)
    private static string BuildResultLine(Finding finding)
    {
        string tag = finding.Status switch
        {
            CheckStatus.Pass => "[PASS]",
            CheckStatus.Fail => "[FAIL]",
            CheckStatus.Warning => "[WARN]",
            _ => "[INFO]"
        };

        string suffix = finding.Status == CheckStatus.Pass
            ? "(PASS)"
            : $"({finding.Status.ToString().ToUpper()} - expected {finding.ExpectedValue})";

        return $"{tag} {finding.CheckId}: {finding.Name} = {finding.CurrentValue} {suffix}";
    }
}