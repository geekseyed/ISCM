namespace ISCM.Domain.Enums;

public enum CheckStatus
{
    NotScanned,
    Pass,
    Fail,
    Unknown,          // جایگزین Warning: شواهد برای تصمیم‌گیری کافی نیست یا تنظیم یافت نشد
    NotApplicable,    // این تنظیم برای این OS/Build صدق نمی‌کند
    Error,            // فرآیند ارزیابی با خطا مواجه شد
    Ignored,          // وضعیت حاکمیتی: توسط اپراتور نادیده گرفته شده
    FalsePositive     // وضعیت حاکمیتی: توسط اپراتور به عنوان خطای مثبت کاذب تأیید شده
}