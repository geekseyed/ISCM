using ISCM.Application.Interfaces;
using ISCM.Application.Evaluators;
using ISCM.Application.Services;
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
    private readonly IBaselineService _baselineService; // ✅ فیلد اضافه شد

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
        _baselineService = baselineService ?? throw new ArgumentNullException(nameof(baselineService)); // ✅ مقداردهی اضافه شد
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
        var scanResult = new ScanResult(hostname, ipAddress, macAddress, osVersion, osBuild, mode);

        // ✅ Phase 3.2: تنظیم BaselineId در ScanResult
        scanResult.BaselineId = defaultBaseline.BaselineId;

        progress?.Report($"[INFO] Collecting system info... Hostname: {hostname}, IP: {ipAddress}");
        progress?.Report("[INFO] Collector: RegistryReader - reading HKLM policies...");
        await Task.Delay(100);

        foreach (var check in _checks)
        {
            await Task.Delay(200);

            try
            {
                // Phase 2.5: Use EvaluateSubControlsAsync for detailed evaluation
                var subControlResults = await check.EvaluateSubControlsAsync();

                // Validate multi-path tests if applicable
                if (check is IMultiPathCheck multiPathCheck)
                {
                    var testResults = await multiPathCheck.RunMultipleTestsAsync();

                    // Add test results to evidence
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

                // Get the control definition from catalog
                var controlDefinition = ControlCatalog.GetByCheckId(check.CheckId);
                if (controlDefinition == null)
                {
                    // Fallback: create a simple definition using check.CheckId as both ControlId and TechnicalCheckId
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

                // ✅ استفاده از EvaluateFromSubControls برای ایجاد Finding با CheckId صحیح
                var finding = _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults);

                scanResult.AddFinding(finding);
                progress?.Report(BuildResultLine(finding));
            }
            catch (Exception ex)
            {
                var errorFinding = new Finding(
                    check.CheckId,
                    "Unknown Check",
                    CheckCategory.System,
                    CheckSeverity.High,
                    CheckStatus.Error,
                    "Crash",
                    "N/A",
                    "The check failed to execute.",
                    errorMessage: ex.Message);

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

        return _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults);
    }

    public async Task<Finding> RescanSubControlAsync(string checkId, string subControlId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        Console.WriteLine($"[INFO] Rescan requested for SubControl {subControlId} within {checkId}");

        // For now, rescan the entire check
        // TODO: After full Phase 1.4 integration, evaluate only the specific SubControl
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