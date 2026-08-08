using ISCM.Application.Interfaces;
using ISCM.Infrastructure.Scanning;
using ISCM.Infrastructure.Scanning.Checks;
using ISCM.Infrastructure.Scanning.Collectors;
using ISCM.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ۱. ثبت Collector اطلاعات سیستم
builder.Services.AddSingleton<WindowsSystemInfoCollector>();

// ۲. ثبت چک‌های امنیتی (هر چکی که ساختیم را اینجا اضافه می‌کنیم)
builder.Services.AddTransient<IHardeningCheck, FirewallDomainProfileCheck>();

// ۳. ثبت اسکنر اصلی
builder.Services.AddScoped<IScanService, WindowsHardeningScanner>();

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