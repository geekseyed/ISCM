using ISCM.Application.Interfaces;
using ISCM.Infrastructure.Reporting;
using ISCM.Infrastructure.Scanning;
using ISCM.Infrastructure.Scanning.Checks;
using ISCM.Infrastructure.Scanning.Collectors;
using ISCM.Web.Components;
using ISCM.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSingleton<WindowsSystemInfoCollector>();

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
builder.Services.AddTransient<IHardeningCheck, AdminAccountCountCheck>();
builder.Services.AddTransient<IHardeningCheck, PasswordLengthCheck>();
builder.Services.AddTransient<IHardeningCheck, LmCompatibilityCheck>();
builder.Services.AddTransient<IHardeningCheck, ProcessCreationAuditingCheck>();
builder.Services.AddTransient<IHardeningCheck, PowerShellLoggingCheck>();
builder.Services.AddTransient<IHardeningCheck, DisableCmdCheck>();
builder.Services.AddTransient<IHardeningCheck, AccountLockoutCheck>();
builder.Services.AddTransient<IHardeningCheck, AdvancedAuditCheck>();
builder.Services.AddTransient<IHardeningCheck, UserRightsCheck>();
builder.Services.AddTransient<IHardeningCheck, LlmnrNetbiosCheck>();
builder.Services.AddTransient<IHardeningCheck, CredentialGuardCheck>();
builder.Services.AddTransient<IHardeningCheck, EventLogSizeCheck>();


builder.Services.AddScoped<IScanService, WindowsHardeningScanner>();
builder.Services.AddScoped<IReportService, HtmlReportGenerator>();
builder.Services.AddScoped<ScanStateService>();
builder.Services.AddScoped<ScanHistoryService>();
builder.Services.AddScoped<ThemeService>();
builder.Services.AddScoped<ReportGateService>();

var app = builder.Build();

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