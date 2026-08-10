using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

public class ScanStateService
{
    public ScanResult? CurrentScanResult { get; set; }
    public bool IsScanning { get; set; } = false; // این اضافه شد
    public event Action? OnChange;

    public void SetScanResult(ScanResult result)
    {
        CurrentScanResult = result;
        OnChange?.Invoke();
    }
}