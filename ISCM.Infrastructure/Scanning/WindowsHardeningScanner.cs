using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Application.Services.Agreement;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Collectors;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning;

/// <summary>
/// Windows hardening scanner — orchestrates check execution, evidence collection,
/// normalization (Phase 6), evaluation, verification path tracking (Phase 8),
/// agreement/disagreement analysis (Phase 9), and typed pipeline (Phase 10).
/// 
/// Phase 9.4: Integrated SubControlAggregationService for agreement analysis.
/// Phase 10.4: Supports both collector-only pattern (IEvidenceCollector) and legacy pattern.
///   - Collector-only: calls CollectEvidenceAsync, then EvaluateSubControlTyped with catalog metadata
///   - Legacy: calls EvaluateSubControlsAsync (backward compatibility)
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
    private readonly SubControlAggregationService _aggregationService;

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
        VerificationPathService verificationPathService,
        SubControlAggregationService aggregationService)
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
        _aggregationService = aggregationService ?? throw new ArgumentNullException(nameof(aggregationService));
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

                // Phase 10.4: Branch based on check type
                List<SubControlResult> subControlResults;

                if (check is IEvidenceCollector collector)
                {
                    // ═══════════════════════════════════════════════════════════════
                    // NEW: Collector-only path (Phase 10.4)
                    // ═══════════════════════════════════════════════════════════════
                    subControlResults = await RunCollectorOnlyPath(
                        collector, controlDefinition, scanContext, hostname, progress);
                }
                else
                {
                    // ═══════════════════════════════════════════════════════════════
                    // LEGACY: Old-style check that still uses EvaluateSubControlsAsync
                    // Will be migrated in subsequent phases (10.5-10.8)
                    // ═══════════════════════════════════════════════════════════════
                    subControlResults = await RunLegacyPath(
                        check, controlDefinition, scanContext, hostname, progress);
                }

                // Phase 9.4: Apply agreement/disagreement analysis (if MultiPathCheck)
                if (check is IMultiPathCheck)
                {
                    _aggregationService.AggregateAll(subControlResults);

                    var agreementSummary = _aggregationService.GetSummary(subControlResults);
                    if (agreementSummary.HasDisagreement)
                    {
                        progress?.Report($"[WARNING] {check.CheckId}: Agreement analysis found {agreementSummary.DisagreementCount} disagreement(s).");
                    }
                    if (agreementSummary.HasIncompleteVerification)
                    {
                        progress?.Report($"[INFO] {check.CheckId}: Agreement analysis found {agreementSummary.IncompleteCount} incomplete verification(s).");
                    }
                }

                // Produce Finding
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
        scanContext.MarkCompleted();
        return scanResult;
    }

    /// <summary>
    /// Phase 10.4: Runs the collector-only path for IEvidenceCollector checks.
    /// 
    /// Flow:
    ///   1. Call CollectEvidenceAsync() to get raw Evidence list
    ///   2. Group evidence by SubControlId
    ///   3. Convert each group to SubControlResult
    ///   4. Validate path capability
    ///   5. Call EvaluateSubControlTyped with catalog metadata
    /// </summary>
    private async Task<List<SubControlResult>> RunCollectorOnlyPath(
        IEvidenceCollector collector,
        ControlDefinition controlDefinition,
        ScanContext scanContext,
        string hostname,
        IProgress<string>? progress)
    {
        var checkId = collector.CollectorId;

        // Step 1: Collect evidence (check does NOT evaluate)
        var evidenceList = await collector.CollectEvidenceAsync();

        if (evidenceList == null || evidenceList.Count == 0)
        {
            progress?.Report($"[WARNING] {checkId}: Collector returned no evidence");
            return new List<SubControlResult>();
        }

        // Step 2-5: Group by SubControlId and build SubControlResults
        var subControlResults = evidenceList
            .GroupBy(e => e.SubControlId ?? checkId)
            .Select(g =>
            {
                var subControlId = g.Key;
                var subControlDef = controlDefinition.SubControls
                    .FirstOrDefault(s => s.SubControlId == subControlId);

                var subResult = new SubControlResult
                {
                    SubControlId = subControlId,
                    Status = CheckStatus.NotScanned,
                    EvidenceItems = g.ToList(),
                    EvaluatedAt = DateTime.UtcNow
                };

                // Enrich evidence with scan context
                foreach (var evidence in subResult.EvidenceItems)
                {
                    if (string.IsNullOrEmpty(evidence.ScanId))
                        evidence.ScanId = scanContext.ScanId;

                    if (string.IsNullOrEmpty(evidence.ParentControlId))
                        evidence.ParentControlId = checkId;

                    if (string.IsNullOrEmpty(evidence.MachineIdentity))
                        evidence.MachineIdentity = hostname;

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
                }

                // Validate path capability
                if (subControlDef != null)
                {
                    var capabilityReport = _verificationPathService.ValidatePathCapability(subControlDef);
                    subResult.PathCapabilityReport = capabilityReport;

                    if (!capabilityReport.IsValid)
                    {
                        progress?.Report($"[WARNING] {subControlId}: Path capability issues: {string.Join(", ", capabilityReport.Errors)}");
                    }
                }

                // Step 5: Evaluate using typed pipeline with catalog metadata
                if (subControlDef != null && !string.IsNullOrWhiteSpace(subControlDef.ExpectedValue))
                {
                    try
                    {
                        _controlEvaluator.EvaluateSubControlTyped(
                            subResult,
                            subControlDef.ExpectedValue,
                            subControlDef.ExpectedValueType,
                            subControlDef.Operator
                        );
                    }
                    catch (Exception evalEx)
                    {
                        subResult.Status = CheckStatus.Error;
                        progress?.Report($"[ERROR] {subControlId}: Typed evaluation failed: {evalEx.Message}");
                    }
                }
                else
                {
                    // No catalog metadata - fallback to Unknown
                    subResult.Status = CheckStatus.Unknown;
                }

                return subResult;
            })
            .ToList();

        return subControlResults;
    }

    /// <summary>
    /// LEGACY path for checks that still use EvaluateSubControlsAsync.
    /// Backward compatibility for checks not yet migrated to collector-only pattern.
    /// </summary>
    private async Task<List<SubControlResult>> RunLegacyPath(
        IHardeningCheck check,
        ControlDefinition controlDefinition,
        ScanContext scanContext,
        string hostname,
        IProgress<string>? progress)
    {
        var subControlResults = await check.EvaluateSubControlsAsync();

        // Validate path capability for each SubControl
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

        // Multi-path verification with agreement (legacy)
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
                    var pathId = $"{subResult.SubControlId}-path-{pathIndex}";
                    var pathStopwatch = Stopwatch.StartNew();

                    var evidence = new Evidence
                    {
                        ScanId = scanContext.ScanId,
                        ParentControlId = check.CheckId,
                        SubControlId = subResult.SubControlId ?? string.Empty,
                        TechnicalCheckId = check.CheckId,
                        PathId = pathId,
                        SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Other,
                        SourceName = result.TestName,
                        AcquisitionCommand = result.TestMethod,
                        RawOutput = result.Details,
                        Evaluation = result.Passed ? CheckStatus.Pass : CheckStatus.Fail,
                        CollectedAtUtc = DateTime.UtcNow,
                        MachineIdentity = hostname
                    };

                    NormalizeEvidence(evidence);
                    _fingerprintService.AssignFingerprint(evidence);

                    if (_freshnessPolicy.CanUseCachedEvidence(scanContext, evidence))
                    {
                        evidence.LifecycleState = EvidenceLifecycleState.Cached;
                    }
                    else
                    {
                        evidence.LifecycleState = EvidenceLifecycleState.Live;
                    }

                    pathStopwatch.Stop();

                    var pathResult = result.Passed
                        ? PathResult.FromTypedEvaluation(
                            pathId: pathId,
                            source: evidence.SourceName,
                            mechanism: evidence.AcquisitionCommand,
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
                        )
                        : PathResult.Fail(
                            pathId: pathId,
                            source: evidence.SourceName,
                            mechanism: evidence.AcquisitionCommand,
                            reason: $"Path {pathIndex} failed: {result.Details}",
                            evidenceId: evidence.EvidenceId
                        );

                    if (!result.Passed)
                    {
                        pathResult.DurationMs = (int)pathStopwatch.ElapsedMilliseconds;
                        pathResult.CollectorName = "WindowsHardeningScanner";
                        pathResult.EvaluatorName = "IMultiPathCheck direct";
                    }

                    subResult.AddPathResult(pathResult);
                    subResult.EvidenceItems.Add(evidence);
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
        }

        return subControlResults;
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

        List<SubControlResult> subControlResults;

        // Phase 10.4: Use collector-only path if available
        if (check is IEvidenceCollector collector)
        {
            subControlResults = await RunCollectorOnlyPath(
                collector, controlDefinition, scanContext, "rescan-host", null);
        }
        else
        {
            // Legacy path
            subControlResults = await check.EvaluateSubControlsAsync();
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