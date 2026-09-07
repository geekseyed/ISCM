using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.3: Base class for hardening checks (Collector-only pattern).
/// 
/// این کلاس پایه چک‌ها را مجبور می‌کند **فقط Collector** باشند:
/// - متد abstract CollectEvidenceAsync باید پیاده‌سازی شود
/// - متدهای EvaluateAsync و EvaluateSubControlsAsync برای backward compatibility حفظ شده‌اند
/// - اما چک‌های جدید فقط باید CollectEvidenceAsync را پیاده‌سازی کنند
/// </summary>
public abstract class BaseHardeningCheck : IHardeningCheck, IEvidenceCollector
{
    public abstract string CheckId { get; }
    public abstract string Name { get; }
    public abstract CheckCategory Category { get; }
    public abstract CheckSeverity Severity { get; }

    // IEvidenceCollector implementation
    public string CollectorId => CheckId;

    /// <summary>
    /// Phase 10.3: Collects evidence without evaluation.
    /// 
    /// Contract:
    /// - Returns List&lt;Evidence&gt; with RawOutput and TypedValue populated
    /// - Evidence.Evaluation MUST be CheckStatus.NotScanned
    /// - Evidence.TypedValue MUST be set (for typed pipeline)
    /// - NO evaluation logic should be performed here
    /// </summary>
    public abstract Task<List<Evidence>> CollectEvidenceAsync();

    /// <summary>
    /// Legacy method - kept for backward compatibility.
    /// New checks should NOT override this; use CollectEvidenceAsync instead.
    /// </summary>
    public virtual Task<Finding> EvaluateAsync()
    {
        // TODO: Phase 10.4 - Scanner will call CollectEvidenceAsync and evaluate
        // For now, throw NotSupportedException to force migration
        throw new NotSupportedException(
            $"Check {CheckId} should use CollectEvidenceAsync(). " +
            $"Evaluation responsibility moved to Scanner in Phase 10.4.");
    }

    /// <summary>
    /// Legacy method - kept for backward compatibility.
    /// New checks should NOT override this; use CollectEvidenceAsync instead.
    /// </summary>
    public virtual Task<List<SubControlResult>> EvaluateSubControlsAsync()
    {
        // TODO: Phase 10.4 - Scanner will call CollectEvidenceAsync and evaluate
        // For now, throw NotSupportedException to force migration
        throw new NotSupportedException(
            $"Check {CheckId} should use CollectEvidenceAsync(). " +
            $"Evaluation responsibility moved to Scanner in Phase 10.4.");
    }
}