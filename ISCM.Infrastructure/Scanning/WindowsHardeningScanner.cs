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

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null)
    {
        // ارسال پیام به UI: شروع اسکن
        progress?.Report("Initializing scan engine...");
        await Task.Delay(500); // نیم ثانیه مکث برای حس خوب

        // ۱. خواندن اطلاعات پایه سیستم (آپدیت شد با ۴ خروجی)
        var (hostname, ipAddress, osName, osBuild) = _systemInfoCollector.Collect();

        // ۲. ساخت ظرف نتایج اسکن (آپدیت شد با فیلدهای جدید)
        var scanResult = new ScanResult(hostname, ipAddress, osName, osBuild, mode);

        progress?.Report("System information collected successfully.");
        await Task.Delay(500);

        // ۳. اجرای تک‌تک بررسی‌ها
        foreach (var check in _checks)
        {
            // ارسال نام چک فعلی به UI
            progress?.Report($"Checking {check.CheckId}: {check.Name}...");

            // تاخیر عمدی ۱ ثانیه‌ای برای شبیه‌سازی اسکن واقعی
            await Task.Delay(1000);

            try
            {
                var finding = await check.EvaluateAsync();
                scanResult.AddFinding(finding);
            }
            catch (Exception ex)
            {
                // اگر یک چک کلاً کرش کرد، نرم‌افزار متوقف نشود، آن چک Error ثبت شود
                var errorFinding = new Finding(
                    check.CheckId,
                    "Unknown Check",
                    CheckCategory.System,
                    CheckSeverity.High,
                    CheckStatus.Error,
                    $"CRASH: {ex.GetType().Name} - {ex.Message}",
                    "N/A",
                    "The check failed to execute.",
                    ex.Message
                );
                scanResult.AddFinding(errorFinding);
            }
        }

        // ۴. پایان اسکن
        progress?.Report("Finalizing scan and calculating compliance score...");
        await Task.Delay(500);

        scanResult.CompleteScan();
        return scanResult;
    }
}