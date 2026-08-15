using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IScanService
{
    // EDIT: تعداد چک‌های ثبت‌شده — برای شمارنده زنده x/15 در UI
    // اصل Contract-First: لایه Web نباید بداند چند چک وجود دارد؛ قرارداد آن را اعلام می‌کند.
    int TotalCheckCount { get; }

    Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null);
}