using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

// این سرویس نتایج اسکن را در حافظه نگه می‌دارد تا همه تب‌ها به آن دسترسی داشته باشند
public class ScanStateService
{
    public ScanResult? CurrentScanResult { get; set; }

    // رویدادی که وقتی اسکن تمام شد، صفحه را آپدیت می‌کند
    public event Action? OnChange;

    public void SetScanResult(ScanResult result)
    {
        CurrentScanResult = result;
        OnChange?.Invoke();
    }
}