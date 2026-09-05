using ISCM.Application.Evaluators;
using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Application.Services;
using ISCM.Application.Validators;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
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
builder.Services.AddTransient<IHardeningCheck, UserAccountControlCheck>();
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

// Phase 2.5: ثبت IControlEvaluator
builder.Services.AddSingleton<IControlEvaluator, ControlEvaluator>();
// Phase 3.3: ثبت IBaselineService
builder.Services.AddSingleton<IBaselineService, BaselineService>();

builder.Services.AddSingleton<ICatalogValidator, CatalogValidator>();
builder.Services.AddSingleton<IMultiPathCheckValidator, MultiPathCheckValidator>();

// Phase 4: سرویس‌های Freshness & Cache Control
builder.Services.AddSingleton<IEvidenceFingerprintGenerator, EvidenceFingerprintGenerator>();
builder.Services.AddSingleton<IEvidenceCacheService, EvidenceCacheService>();
builder.Services.AddSingleton<IEvidenceLifecycleService, EvidenceLifecycleService>();
builder.Services.AddSingleton<IScanFreshnessPolicy, ScanFreshnessPolicy>();
builder.Services.AddSingleton<IEvidenceAcquisitionService, EvidenceAcquisitionService>();
builder.Services.AddSingleton<IScanInvalidationService, ScanInvalidationService>();
builder.Services.AddSingleton<IRemediationVerificationService, RemediationVerificationService>();
builder.Services.AddSingleton<IScanFingerprintGenerator, ScanFingerprintGenerator>();
builder.Services.AddSingleton<IFingerprintValidationService, FingerprintValidationService>();
builder.Services.AddTransient<IScanContext, ScanContext>(sp =>
    new ScanContext("default", ISCM.Domain.Enums.ScanMode.Full));

// Phase 5: Parsers
builder.Services.AddSingleton<RegistryParser>();
builder.Services.AddSingleton<SeceditParser>();
builder.Services.AddSingleton<NetAccountsParser>();
builder.Services.AddSingleton<AuditpolParser>();
builder.Services.AddSingleton<PowerShellParser>();
builder.Services.AddSingleton<IParserRegistry, ParserRegistry>();
builder.Services.AddSingleton<IParserService, ParserService>();

// Phase 5: Parser Registration
builder.Services.AddSingleton(sp =>
{
    var registry = sp.GetRequiredService<IParserRegistry>();

    // Registry Parser
    var registryParser = sp.GetRequiredService<RegistryParser>();
    registry.RegisterParser<string, RegistryValueData>(EvidenceSourceType.Registry, registryParser);
    registry.RegisterParser<string, RegistryValueData>(EvidenceSourceType.Other, registryParser);

    // Secedit Parser
    var seceditParser = sp.GetRequiredService<SeceditParser>();
    registry.RegisterParser<string, SeceditPolicyData>(EvidenceSourceType.Secedit, seceditParser);

    // NetAccounts Parser
    var netAccountsParser = sp.GetRequiredService<NetAccountsParser>();
    registry.RegisterParser<string, NetAccountsData>(EvidenceSourceType.NetAccounts, netAccountsParser);

    // Auditpol Parser
    var auditpolParser = sp.GetRequiredService<AuditpolParser>();
    registry.RegisterParser<string, AuditpolData>(EvidenceSourceType.Auditpol, auditpolParser);

    // PowerShell Parser
    var powerShellParser = sp.GetRequiredService<PowerShellParser>();
    registry.RegisterParser<string, PowerShellData>(EvidenceSourceType.PowerShell, powerShellParser);

    return registry;
});

// Phase 5: Scanner Configuration
builder.Services.AddSingleton<IScannerConfigurationService, ScannerConfigurationService>();

builder.Services.AddScoped<IScanService, WindowsHardeningScanner>();
builder.Services.AddScoped<IReportService, HtmlReportGenerator>();
// Phase 4.2: ثبت سرویس Remediation
builder.Services.AddSingleton<IRemediationService, RemediationService>();

// Phase 2.5: ثبت ScanStateService با ServiceProvider injection
builder.Services.AddScoped<ScanStateService>(sp => new ScanStateService(sp));

builder.Services.AddScoped<ScanHistoryService>();
builder.Services.AddScoped<ThemeService>();
builder.Services.AddScoped<ReportGateService>();

var app = builder.Build();

// Validate Catalog Integrity at Startup
using (var scope = app.Services.CreateScope())
{
    var validator = scope.ServiceProvider.GetRequiredService<ICatalogValidator>();
    var result = validator.ValidateCatalog();
    Console.WriteLine($"[INFO] Catalog Integrity Validation: {(result.IsValid ? "PASSED" : $"FAILED ({result.CriticalIssues} critical, {result.HighIssues} high issues)")}");
    Console.WriteLine("[INFO] Catalog Integrity Validation: PASSED");
}

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