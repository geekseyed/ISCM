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
        progress?.Report("Initializing scan engine...");
        await Task.Delay(500);

        // دریافت ۴ مقدار از کلکتور (شامل OsBuild)
        var (hostname, ipAddress, osVersion, osBuild) = _systemInfoCollector.Collect();

        // ساخت آبجکت ScanResult با ۵ پارامتر
        var scanResult = new ScanResult(hostname, ipAddress, osVersion, osBuild, mode);

        progress?.Report("System information collected successfully.");
        await Task.Delay(500);

        foreach (var check in _checks)
        {
            progress?.Report($"Checking {check.CheckId}: {check.Name}...");
            await Task.Delay(1000);

            try
            {
                var finding = await check.EvaluateAsync();
                scanResult.AddFinding(finding);
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
                    ex.Message
                );
                scanResult.AddFinding(errorFinding);
            }
        }

        progress?.Report("Finalizing scan and calculating compliance score...");
        await Task.Delay(500);

        scanResult.CompleteScan();
        return scanResult;
    }
}