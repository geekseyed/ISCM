using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IScanService
{
    int TotalCheckCount { get; }

    Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null);

    // EDIT (پیش‌نیاز مرحله ب): اسکن مجددِ فقط یک چک، برای دکمه Rescan
    Task<Finding> RescanCheckAsync(string checkId);
}