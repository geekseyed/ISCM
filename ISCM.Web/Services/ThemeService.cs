namespace ISCM.Web.Services;

// EDIT: سرویس سبک‌دهی (Theme) — دقیقاً با همان الگوی Event-Driven سرویس ScanStateService ساخته شده
// تا با تغییر تم، تمام کامپوننت‌هایی که Subscribe کرده‌اند فوراً Re-render شوند.
public class ThemeService
{
    // EDIT: پیش‌فرض طبق طرح، حالت تاریک است.
    public bool IsDark { get; private set; } = true;

    public event Action? OnChange;

    // EDIT: جابجایی بین تم تاریک و روشن.
    public void ToggleTheme()
    {
        IsDark = !IsDark;
        OnChange?.Invoke();
    }
}