using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

public class ScanStateService
{
    public ScanResult? CurrentScanResult { get; set; }

    // متغیرهای مربوط به وضعیت اسکن که در پس‌زمینه می‌مانند
    public bool IsScanning { get; set; }
    public List<string> ConsoleLogs { get; set; } = new();

    public event Action? OnChange;

    public void SetScanning(bool isScanning)
    {
        IsScanning = isScanning;
        if (!isScanning) ConsoleLogs.Clear(); // وقتی اسکن تمام شد یا لغو شد، لاگ‌ها پاک شوند
        OnChange?.Invoke();
    }

    public void AddLog(string log)
    {
        ConsoleLogs.Add(log);
        OnChange?.Invoke();
    }

    public void SetScanResult(ScanResult result)
    {
        CurrentScanResult = result;
        OnChange?.Invoke();
    }
}