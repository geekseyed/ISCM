using ISCM.Domain.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Phase 10.3: Interface for evidence-only collectors.
/// 
/// این Interface مسئولیت چک‌ها را به **فقط جمع‌آوری** محدود می‌کند:
/// - چک‌ها فقط Evidence تولید می‌کنند (RawOutput + TypedValue)
/// - چک‌ها **نباید** ارزیابی کنند (Evaluation = NotScanned)
/// - Scanner مسئول ارزیابی تایپ‌شده با استفاده از کاتالوگ است
/// 
/// این قرارداد Single Responsibility Principle را اجرا می‌کند:
/// - Check = جمع‌آوری داده خام
/// - Scanner = ارزیابی تایپ‌شده
/// </summary>
public interface IEvidenceCollector
{
    /// <summary>
    /// Unique identifier for this collector (e.g., "PWD-001").
    /// </summary>
    string CollectorId { get; }

    /// <summary>
    /// Human-readable name of this collector.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Collects evidence from the system without evaluating it.
    /// 
    /// Contract:
    /// - Returns List&lt;Evidence&gt; with RawOutput and TypedValue populated
    /// - Evidence.Evaluation MUST be CheckStatus.NotScanned
    /// - Evidence.TypedValue MUST be set (for typed pipeline)
    /// - NO evaluation logic should be performed here
    /// </summary>
    /// <returns>List of collected Evidence items</returns>
    Task<List<Evidence>> CollectEvidenceAsync();
}