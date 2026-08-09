using ISCM.Application.Interfaces;
using ISCM.Infrastructure.Reporting;
using ISCM.Infrastructure.Scanning;
using ISCM.Infrastructure.Scanning.Checks;
using ISCM.Infrastructure.Scanning.Collectors;
using ISCM.Web.Components;
using ISCM.Web.Services; // اضافه شد

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ۱. ثبت Collector اطلاعات سیستم
builder.Services.AddSingleton<WindowsSystemInfoCollector>();

// ۲. ثبت چک‌های امنیتی
builder.Services.AddTransient<IHardeningCheck, FirewallDomainProfileCheck>();
builder.Services.AddTransient<IHardeningCheck, SmbV1ProtocolCheck>();
builder.Services.AddTransient<IHardeningCheck, AutoRunDisabledCheck>();
builder.Services.AddTransient<IHardeningCheck, WindowsDefenderCheck>();
builder.Services.AddTransient<IHardeningCheck, GuestAccountCheck>();
builder.Services.AddTransient<IHardeningCheck, UacCheck>();
builder.Services.AddTransient<IHardeningCheck, UsbStorageCheck>();
builder.Services.AddTransient<IHardeningCheck, WindowsUpdateCheck>();
builder.Services.AddTransient<IHardeningCheck, AutoLogonCheck>();
builder.Services.AddTransient<IHardeningCheck, RdpNlaCheck>();

// ۳. ثبت اسکنر اصلی
builder.Services.AddScoped<IScanService, WindowsHardeningScanner>();

// ۴. ثبت سیستم تولید گزارش
builder.Services.AddScoped<IReportService, HtmlReportGenerator>();

// ۵. ثبت سرویس اشتراک وضعیت اسکن (جدید)
builder.Services.AddScoped<ScanStateService>();
// 6. ثبت سرویس اشتراک وضعیت اسکن
builder.Services.AddScoped<ScanStateService>();

// 7. ثبت سرویس تاریخچه اسکن
builder.Services.AddScoped<ScanHistoryService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();