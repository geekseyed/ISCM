using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Collectors;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning;

/// <summary>
/// Windows hardening scanner — orchestrates check execution, evidence collection,
/// normalization (Phase 6), evaluation, and verification path tracking (Phase 8).
/// 
/// Phase 8.4: Integrated VerificationPath and PathResult into scan pipeline.
/// Each IMultiPathCheck test now produces a PathResult with independent evidence.
/// </summary>
public class WindowsHardeningScanner : IScanService
{
    private readonly WindowsSystemInfoCollector _systemInfoCollector;
    private readonly IEnumerable<IHardeningCheck> _checks;
    private readonly IMultiPathCheckValidator _multiPathValidator;
    private readonly IControlEvaluator _controlEvaluator;
    private readonly IBaselineService _baselineService;
    private readonly IEvidenceAcquisitionService _acquisitionService;
    private readonly IScanFreshnessPolicy _freshnessPolicy;
    private readonly IFingerprintValidationService _fingerprintService;
    private readonly IScanInvalidationService _invalidationService;
    private readonly INormalizationService _normalizationService;
    private readonly VerificationPathService _verificationPathService;

    public WindowsHardeningScanner(
        WindowsSystemInfoCollector systemInfoCollector,
        IEnumerable<IHardeningCheck> checks,
        IMultiPathCheckValidator multiPathValidator,
        IControlEvaluator controlEvaluator,
        IBaselineService baselineService,
        IEvidenceAcquisitionService acquisitionService,
        IScanFreshnessPolicy freshnessPolicy,
        IFingerprintValidationService fingerprintService,
        IScanInvalidationService invalidationService,
        INormalizationService normalizationService,
        VerificationPathService verificationPathService)
    {
        _systemInfoCollector = systemInfoCollector ?? throw new ArgumentNullException(nameof(systemInfoCollector));
        _checks = checks ?? throw new ArgumentNullException(nameof(checks));
        _multiPathValidator = multiPathValidator ?? throw new ArgumentNullException(nameof(multiPathValidator));
        _controlEvaluator = controlEvaluator ?? throw new ArgumentNullException(nameof(controlEvaluator));
        _baselineService = baselineService ?? throw new ArgumentNullException(nameof(baselineService));
        _acquisitionService = acquisitionService ?? throw new ArgumentNullException(nameof(acquisitionService));
        _freshnessPolicy = freshnessPolicy ?? throw new ArgumentNullException(nameof(freshnessPolicy));
        _fingerprintService = fingerprintService ?? throw new ArgumentNullException(nameof(fingerprintService));
        _invalidationService = invalidationService ?? throw new ArgumentNullException(nameof(invalidationService));
        _normalizationService = normalizationService ?? throw new ArgumentNullException(nameof(normalizationService));
        _verificationPathService = verificationPathService ?? throw new ArgumentNullException(nameof(verificationPathService));
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

        // Phase 4: Create new ScanContext with new ScanId
        var scanContext = new ScanContext(hostname, mode);

        var scanResult = new ScanResult(hostname, ipAddress, macAddress, osVersion, osBuild, mode, hostname)
        {
            BaselineId = defaultBaseline.BaselineId,
            ScannerVersion = scanContext.ScannerVersion
        };

        progress?.Report($"[INFO] Scan started: ScanId={scanContext.ScanId}");
        progress?.Report($"[INFO] Collecting system info... Hostname: {hostname}, IP: {ipAddress}");
        progress?.Report("[INFO] Collector: RegistryReader - reading HKLM policies...");
        await Task.Delay(100);

        foreach (var check in _checks)
        {
            await Task.Delay(200);

            try
            {
                var subControlResults = await check.EvaluateSubControlsAsync();

                // Phase 8.4: Get ControlDefinition for path capability validation
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

                // Phase 8.4: Validate path capability for each SubControl
                foreach (var subResult in subControlResults)
                {
                    var subControlDef = controlDefinition.SubControls
                        .FirstOrDefault(s => s.SubControlId == subResult.SubControlId);

                    if (subControlDef != null)
                    {
                        var capabilityReport = _verificationPathService.ValidatePathCapability(subControlDef);
                        subResult.PathCapabilityReport = capabilityReport;

                        if (!capabilityReport.IsValid)
                        {
                            progress?.Report($"[WARNING] {subResult.SubControlId}: Path capability issues: {string.Join(", ", capabilityReport.Errors)}");
                        }
                    }
                }

                if (check is IMultiPathCheck multiPathCheck)
                {
                    var testResults = await multiPathCheck.RunMultipleTestsAsync();
                    var pathIndex = 0;

                    foreach (var result in testResults)
                    {
                        pathIndex++;
                        Enum.TryParse<EvidenceSourceType>(result.TestMethod, true, out var parsedSourceType);

                        foreach (var subResult in subControlResults)
                        {
                            // Phase 8.4: Generate unique PathId for this path
                            var pathId = $"{subResult.SubControlId}-path-{pathIndex}";

                            var pathStopwatch = Stopwatch.StartNew();

                            // Phase 4: Use acquisition service for live evidence
                            var evidence = new Evidence
                            {
                                ScanId = scanContext.ScanId,
                                ParentControlId = check.CheckId,
                                SubControlId = subResult.SubControlId ?? string.Empty,
                                TechnicalCheckId = check.CheckId,
                                PathId = pathId,
                                SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Other,
                                SourceName = result.TestName,
                                AcquisitionCommand = result.TestMethod,  // ← FIX: AcquisitionMechanism → AcquisitionCommand
                                RawOutput = result.Details,
                                Evaluation = result.Passed ? CheckStatus.Pass : CheckStatus.Fail,
                                CollectedAtUtc = DateTime.UtcNow,
                                MachineIdentity = hostname
                            };

                            // Phase 6: Normalize raw output into typed EvidenceValue
                            NormalizeEvidence(evidence);

                            // Phase 4: Assign fingerprint and validate
                            _fingerprintService.AssignFingerprint(evidence);

                            // Phase 4: Apply freshness policy
                            if (_freshnessPolicy.CanUseCachedEvidence(scanContext, evidence))
                            {
                                evidence.LifecycleState = EvidenceLifecycleState.Cached;
                            }
                            else
                            {
                                evidence.LifecycleState = EvidenceLifecycleState.Live;
                            }

                            pathStopwatch.Stop();

                            // Phase 8.4: Create PathResult for this path
                            var pathResult = PathResult.FromTypedEvaluation(
    pathId: pathId,
    source: evidence.SourceName,
    mechanism: evidence.AcquisitionCommand,  // ← FIX: AcquisitionMechanism → AcquisitionCommand
    typedEvaluation: Domain.ValueObjects.EvaluationResult.Pass(
        reason: $"Path {pathIndex} passed: {result.Details}",
        details: Domain.ValueObjects.EvaluationResult.BuildDetails(
            actual: evidence.TypedValue?.RawString ?? evidence.RawOutput ?? "(no value)",
            expected: subResult.EvidenceItems.FirstOrDefault()?.ExpectedValue ?? "N/A",
            op: Operator.Equals,
            valueType: evidence.TypedValue?.ValueType.ToString() ?? "Unknown"
        )),
    evidenceId: evidence.EvidenceId,
    collectorName: "WindowsHardeningScanner",
    parserName: "Normalized via INormalizationService",
    normalizerName: "Phase 6 Normalizer",
    evaluatorName: "IMultiPathCheck direct",
    durationMs: (int)pathStopwatch.ElapsedMilliseconds
);

                            // If the path failed, override with Fail result
                            if (!result.Passed)
                            {
                                pathResult = PathResult.Fail(
                                    pathId: pathId,
                                    source: evidence.SourceName,
                                    mechanism: evidence.AcquisitionCommand,  // ← FIX: AcquisitionMechanism → AcquisitionCommand
                                    reason: $"Path {pathIndex} failed: {result.Details}",
                                    evidenceId: evidence.EvidenceId
                                );
                                pathResult.DurationMs = (int)pathStopwatch.ElapsedMilliseconds;
                                pathResult.CollectorName = "WindowsHardeningScanner";
                                pathResult.EvaluatorName = "IMultiPathCheck direct";
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

                    var finding = _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults, check.CheckId);

                    scanResult.AddFinding(finding);
                    progress?.Report(BuildResultLine(finding));
                }
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
        scanContext.MarkCompleted();
        return scanResult;
    }

    /// <summary>
    /// Phase 6: Normalize raw evidence output via parser → normalizer pipeline.
    /// On success: evidence.TypedValue is set to typed EvidenceValue.
    /// On failure: TypedValue stays null; raw kept only for legacy evaluation.
    /// 
    /// Phase 7.6: TypedValue is now consumed by typed evaluation pipeline (when available).
    /// </summary>
    private void NormalizeEvidence(Evidence evidence)
    {
        if (string.IsNullOrWhiteSpace(evidence.RawOutput))
        {
            evidence.ParsedValue = string.Empty;
            return;
        }

        var normalized = _normalizationService.NormalizeRaw(evidence.RawOutput, evidence.SourceType);

        if (normalized.IsSuccess && normalized.Value != null)
        {
            evidence.TypedValue = normalized.Value;
            evidence.ParsedValue = normalized.Value.RawString;
        }
        else
        {
            // Normalization failed explicitly: TypedValue remains null.
            // Legacy string evaluation may still use ParsedValue during migration.
            evidence.ParsedValue = evidence.RawOutput.Trim();
        }
    }

    public async Task<Finding> RescanCheckAsync(string checkId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        // Phase 4: Invalidate old evidence for this check
        _invalidationService.InvalidateForRemediation("rescan", checkId);

        // Phase 4: Create new ScanContext for rescan
        var scanContext = new ScanContext(checkId, ScanMode.Rescan);

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

        return _controlEvaluator.EvaluateFromSubControls(controlDefinition, subControlResults, checkId);
    }

    public async Task<Finding> RescanSubControlAsync(string checkId, string subControlId)
    {
        var check = _checks.FirstOrDefault(c => c.CheckId == checkId)
            ?? throw new InvalidOperationException($"Check '{checkId}' not found.");

        Console.WriteLine($"[INFO] Rescan requested for SubControl {subControlId} within {checkId}");

        // Phase 4: Invalidate old evidence for this subcontrol
        _invalidationService.InvalidateForRemediation("rescan", subControlId);

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