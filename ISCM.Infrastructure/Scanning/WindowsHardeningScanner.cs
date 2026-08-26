using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Collectors;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning;

public class WindowsHardeningScanner : IScanService
{
    private readonly WindowsSystemInfoCollector _systemInfoCollector;
    private readonly IEnumerable<IHardeningCheck> _checks;
    private readonly IMultiPathCheckValidator _multiPathValidator;
    private readonly IControlEvaluator _controlEvaluator;
    private readonly IBaselineService _baselineService;

    public WindowsHardeningScanner(
        WindowsSystemInfoCollector systemInfoCollector,
        IEnumerable<IHardeningCheck> checks,
        IMultiPathCheckValidator multiPathValidator,
        IControlEvaluator controlEvaluator,
        IBaselineService baselineService)
    {
        _systemInfoCollector = systemInfoCollector ?? throw new ArgumentNullException(nameof(systemInfoCollector));
        _checks = checks ?? throw new ArgumentNullException(nameof(checks));
        _multiPathValidator = multiPathValidator ?? throw new ArgumentNullException(nameof(multiPathValidator));
        _controlEvaluator = controlEvaluator ?? throw new ArgumentNullException(nameof(controlEvaluator));
        _baselineService = baselineService ?? throw new ArgumentNullException(nameof(baselineService));
    }

    public int TotalCheckCount => _checks.Count();

    public async Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null)
    {
        progress?.Report("[INFO] DefenDoor Scanner initialized");
        await Task.Delay(100);

        var defaultBaseline = _baselineService.GetDefaultBaseline();
        progress?.Report($"[INFO] Loading baseline: {defaultBaseline.Name} v{defaultBaseline.Version} ({TotalCheckCount} rules)");
        await Task.Delay(50);

        var (hostname, ipAddress, macAddress, osVersion, osBuild) = _systemInfoCollector.Collect();
        var scanResult = new ScanResult(hostname, ipAddress, macAddress, osVersion, osBuild, mode)
        {
            BaselineId = defaultBaseline.BaselineId
        };

        progress?.Report($"[INFO] Collecting system info... Hostname: {hostname}, IP: {ipAddress}");
        progress?.Report("[INFO] Collector: RegistryReader - reading HKLM policies...");
        await Task.Delay(100);

        foreach (var check in _checks)
        {
            await Task.Delay(200);

            try
            {
                // Phase 2.5: ارزیابی دقیق هر SubControl
                var subControlResults = await check.EvaluateSubControlsAsync();

                // اعتبارسنجی چندمسیره در صورت پشتیبانی چک
                if (check is IMultiPathCheck multiPathCheck)
                {
                    var testResults = await multiPathCheck.RunMultipleTestsAsync();

                    foreach (var result in testResults)
                    {
                        foreach (var subResult in subControlResults)
                        {
                            subResult.EvidenceItems.Add(new Evidence
                            {
                                SourceType = result.TestMethod,
                                SourceName = result.TestName,
                                RawOutput = result.Details,
                                Evaluation = result.Passed ? CheckStatus.Pass : CheckStatus.Fail,
                                Timestamp = DateTime.UtcNow
                            });
                        }
                    }

                    if (testResults.Count >= 3)
                    {
                        progress?.Report($"  ├─ Test 1 ({testResults[0].TestMethod}): {(testResults[0].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                        progress?.Report($"  ├─ Test 2 ({testResults[1].TestMethod}): {(testResults[1].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                        progress?.Report($"  └─ Test 3 ({testResults[2].TestMethod}): {(testResults[2].Passed ? "Pass ✓" : "Fail ✗")}");
                        await Task.Delay(30);
                    }

                    var validationResult = _multiPathValidator.Validate(check.CheckId, testResults);
                    if (!validationResult.IsValid)
                    {
                        progress?.Report($"[WARNING] {check.CheckId}: MultiPath validation failed: {string.Join(", ", validationResult.Errors)}");
                    }
                    else if (validationResult.Warnings.Any())
                    {
                        progress?.Report($"[INFO] {check.CheckId}: {string.Join(", ", validationResult.Warnings)}");
                    }
                }

                var controlDefinition = ControlCatalog.GetByCheckId(check.CheckId);
                if (controlDefinition == null)
                {
                    controlDefinition = new ControlDefinition
                    {
                        ControlId = check.CheckId,
                        Title = check.Name,
                        Category = check.Category,
                        Severity = check.Severity,
                        IsBaseline = true,
                        TechnicalCheckIds = new() { check.CheckId },
                        SubControls = new()
                    };
                }

                // ✅ اصلاح فاز 4: عبور check.CheckId تا UAC/LM/ADM روی هم بازنویسی نشوند
                var finding = _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults, check.CheckId);

                scanResult.AddFinding(finding);
                progress?.Report(BuildResultLine(finding));
            }
            catch (Exception ex)
            {
                var errorFinding = new Finding(
                    checkId: check.CheckId,
                    name: check.Name,
                    category: check.Category,
                    severity: check.Severity,
                    status: CheckStatus.Error,
                    currentValue: "Crash",
                    expectedValue: "N/A",
                    description: "The check failed to execute.",
                    errorMessage: ex.Message,
                    registryPath: string.Empty,
                    cisReference: null,
                    riskScore: (int)check.Severity * 20,
                    sourceType: "Error",
                    sourceCommand: string.Empty,
                    fixTools: new List<string>(),
                    subChecks: null,
                    recommendation: "Investigate the check execution error."
                );

                scanResult.AddFinding(errorFinding);
                progress?.Report($"[ERROR] {check.CheckId}: {check.Name} = Crash ({ex.Message})");
            }
        }

        progress?.Report("[INFO] Finalizing scan and calculating compliance score...");
        await Task.Delay(100);

        scanResult.CompleteScan();
        return scanResult;
    }

    public async Task<Finding> RescanCheckAsync(string checkId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        var subControlResults = await check.EvaluateSubControlsAsync();
        var controlDefinition = ControlCatalog.GetByCheckId(checkId);

        if (controlDefinition == null)
        {
            controlDefinition = new ControlDefinition
            {
                ControlId = checkId,
                Title = check.Name,
                Category = check.Category,
                Severity = check.Severity,
                IsBaseline = true,
                TechnicalCheckIds = new() { checkId },
                SubControls = new()
            };
        }

        // ✅ عبور checkId در Rescan هم
        return _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults, checkId);
    }

    public async Task<Finding> RescanSubControlAsync(string checkId, string subControlId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        Console.WriteLine($"[INFO] Rescan requested for SubControl {subControlId} within {checkId}");

        // فعلاً کل چک اسکن مجدد می‌شود
        return await RescanCheckAsync(checkId);
    }

    private static string BuildResultLine(Finding finding)
    {
        string tag = finding.Status switch
        {
            CheckStatus.Pass => "[PASS]",
            CheckStatus.Fail => "[FAIL]",
            CheckStatus.Unknown => "[UNKNOWN]",
            CheckStatus.Error => "[ERROR]",
            _ => "[INFO]"
        };

        string subControlInfo = finding.SubControlId != null ? $" [{finding.SubControlId}]" : "";
        string suffix = finding.Status == CheckStatus.Pass
            ? "(PASS)"
            : $"({finding.Status.ToString().ToUpper()} - expected {finding.ExpectedValue})";

        return $"{tag} {finding.CheckId}{subControlInfo}: {finding.Name} = {finding.CurrentValue} {suffix}";
    }
}