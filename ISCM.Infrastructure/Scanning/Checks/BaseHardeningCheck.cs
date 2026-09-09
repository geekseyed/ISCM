using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 11.5: Base class for hardening checks (Collector-only pattern).
///
/// این کلاس پایه چک‌ها را مجبور می‌کند **فقط Collector** باشند:
/// - متد abstract CollectEvidenceAsync باید پیاده‌سازی شود
/// - چک‌ها فقط Evidence تولید می‌کنند (RawOutput + TypedValue)
/// - Scanner مسئول ارزیابی تایپ‌شده با استفاده از کاتالوگ است
///
/// این قرارداد Single Responsibility Principle را اجرا می‌کند:
/// - Check = جمع‌آوری داده خام + metadata
/// - Scanner = ارزیابی تایپ‌شده با catalog metadata
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
    /// Collects evidence without evaluation.
    ///
    /// Contract:
    /// - Returns List&lt;Evidence&gt; with RawOutput and TypedValue populated
    /// - Evidence.Evaluation MUST be CheckStatus.NotScanned
    /// - Evidence.TypedValue MUST be set (for typed pipeline)
    /// - NO evaluation logic should be performed here
    /// </summary>
    public abstract Task<List<Evidence>> CollectEvidenceAsync();
}