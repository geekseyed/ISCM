using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full)
    {
        // ۱. خواندن اطلاعات پایه سیستم
        var (hostname, ipAddress, osVersion) = _systemInfoCollector.Collect();

        // ۲. ساخت ظرف نتایج اسکن
        var scanResult = new ScanResult(hostname, ipAddress, osVersion, mode);

        // ۳. اجرای تک‌تک بررسی‌ها (مثل فایروال)
        foreach (var check in _checks)
        {
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
                    "Crash",
                    "N/A",
                    "The check failed to execute.",
                    ex.Message
                );
                scanResult.AddFinding(errorFinding);
            }
        }

        // ۴. پایان اسکن
        scanResult.CompleteScan();
        return scanResult;
    }
}