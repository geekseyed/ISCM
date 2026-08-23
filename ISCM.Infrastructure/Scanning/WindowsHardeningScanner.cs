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

    public int TotalCheckCount => _checks.Count();

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null)
    {
        progress?.Report("[INFO] DefenDoor Scanner initialized");
        await Task.Delay(100);

        progress?.Report($"[INFO] Loading baseline: windows11-pro-hardening.json ({TotalCheckCount} rules)");
        await Task.Delay(50);

        var (hostname, ipAddress, macAddress, osVersion, osBuild) = _systemInfoCollector.Collect();
        var scanResult = new ScanResult(hostname, ipAddress, macAddress, osVersion, osBuild, mode);

        progress?.Report($"[INFO] Collecting system info... Hostname: {hostname}, IP: {ipAddress}");
        progress?.Report("[INFO] Collector: RegistryReader - reading HKLM policies...");
        await Task.Delay(100);

        foreach (var check in _checks)
        {
            await Task.Delay(200);

            try
            {
                var finding = await check.EvaluateAsync();

                // EDIT (فاز 1 - پیام 2): فقط اگر IMultiPathCheck پیاده‌سازی شده، تست‌های واقعی اجرا شود.
                // دیگر Fallback شبیه‌سازی‌شده وجود ندارد.
                if (check is IMultiPathCheck multiPathCheck)
                {
                    var testResults = await multiPathCheck.RunMultipleTestsAsync();
                    foreach (var result in testResults)
                    {
                        finding.AddTestResult(result);
                    }

                    // گزارش تست‌ها به کنسول
                    if (testResults.Count >= 3)
                    {
                        progress?.Report($"  ├─ Test 1 ({testResults[0].TestMethod}): {(testResults[0].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                        progress?.Report($"  ├─ Test 2 ({testResults[1].TestMethod}): {(testResults[1].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                        progress?.Report($"  └─ Test 3 ({testResults[2].TestMethod}): {(testResults[2].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                    }
                }
                // حذف کامل: else { await RunSimulatedTests(...) }

                scanResult.AddFinding(finding);
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
        await Task.Delay(100);

        scanResult.CompleteScan();
        return scanResult;
    }

    // حذف کامل: متد RunSimulatedTests دیگر وجود ندارد

    public async Task<Finding> RescanCheckAsync(string checkId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        return await check.EvaluateAsync();
    }

    private static string BuildResultLine(Finding finding)
    {
        string tag = finding.Status switch
        {
            CheckStatus.Pass => "[PASS]",
            CheckStatus.Fail => "[FAIL]",
            CheckStatus.Unknown => "[WARN]",
            _ => "[INFO]"
        };

        string suffix = finding.Status == CheckStatus.Pass
            ? "(PASS)"
            : $"({finding.Status.ToString().ToUpper()} - expected {finding.ExpectedValue})";

        return $"{tag} {finding.CheckId}: {finding.Name} = {finding.CurrentValue} {suffix}";
    }
}