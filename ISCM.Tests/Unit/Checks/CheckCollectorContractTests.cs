using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;
using System.Reflection;

namespace ISCM.Tests.Unit.Checks;

/// <summary>
/// Golden tests for Phase 10.3 — Check Collector Contract
/// 
/// این تست‌ها تضمین می‌کنند که چک‌ها **فقط Collector** هستند:
/// 1. چک‌ها فقط Evidence تولید می‌کنند (نه Status)
/// 2. چک‌ها نباید از IEvidenceEvaluator استفاده کنند
/// 3. Evidence.Evaluation باید NotScanned باشد (چک ارزیابی نمی‌کند)
/// 4. Evidence.TypedValue باید ست شود (برای pipeline تایپ‌شده)
/// 
/// این قرارداد Single Responsibility Principle را اجرا می‌کند:
/// - چک = جمع‌آوری داده خام
/// - Scanner = ارزیابی تایپ‌شده با استفاده از کاتالوگ
/// </summary>
public class CheckCollectorContractTests
{
    [Fact]
    public void BaseHardeningCheck_ShouldNotDependOnEvaluator()
    {
        // BaseHardeningCheck نباید فیلد یا property از نوع IEvidenceEvaluator داشته باشد
        var baseType = typeof(BaseHardeningCheck);
        var fields = baseType.GetFields(BindingFlags.NonPublic | BindingFlags.Instance);

        var evaluatorFields = fields
            .Where(f => f.FieldType.Name.Contains("Evaluator") ||
                        f.FieldType.Name.Contains("IEvidenceEvaluator"))
            .ToList();

        evaluatorFields.Should().BeEmpty(
            "BaseHardeningCheck should not depend on IEvidenceEvaluator. " +
            "Evaluation responsibility belongs to Scanner, not Check.");
    }

    [Fact]
    public void PasswordLengthCheck_ShouldNotHaveEvaluatorField()
    {
        // PasswordLengthCheck نباید فیلد _evaluator داشته باشد
        var checkType = typeof(PasswordLengthCheck);
        var fields = checkType.GetFields(BindingFlags.NonPublic | BindingFlags.Instance);

        var evaluatorFields = fields
            .Where(f => f.Name.Contains("evaluator", StringComparison.OrdinalIgnoreCase) ||
                        f.FieldType.Name.Contains("Evaluator"))
            .ToList();

        evaluatorFields.Should().BeEmpty(
            "PasswordLengthCheck should not have _evaluator field. " +
            "Use CollectEvidenceAsync() instead of EvaluateSubControlsAsync().");
    }

    [Fact]
    public async Task PasswordLengthCheck_CollectEvidenceAsync_ReturnsEvidenceWithTypedValue()
    {
        // Arrange
        var check = new PasswordLengthCheck();

        // Act - چک باید متد CollectEvidenceAsync داشته باشد
        var collectMethod = check.GetType().GetMethod("CollectEvidenceAsync");

        collectMethod.Should().NotBeNull(
            "PasswordLengthCheck must implement CollectEvidenceAsync() method");

        if (collectMethod != null)
        {
            var task = (Task<List<Evidence>>)collectMethod.Invoke(check, null)!;
            var evidenceList = await task;

            // Assert
            evidenceList.Should().NotBeEmpty("check must produce at least one Evidence");

            foreach (var evidence in evidenceList)
            {
                // Evidence.Evaluation باید NotScanned باشد (چک ارزیابی نمی‌کند)
                evidence.Evaluation.Should().Be(CheckStatus.NotScanned,
                    "Check should only collect evidence, not evaluate it. " +
                    "Scanner will evaluate using catalog metadata.");

                // Evidence.TypedValue باید ست شود (برای pipeline تایپ‌شده)
                evidence.TypedValue.Should().NotBeNull(
                    "Evidence.TypedValue must be set for typed pipeline evaluation.");

                // Evidence.RawOutput باید ست شود
                evidence.RawOutput.Should().NotBeNullOrWhiteSpace(
                    "Evidence.RawOutput must contain the raw collected data.");
            }
        }
    }

    [Fact]
    public void PasswordLengthCheck_ShouldImplementICollector()
    {
        // PasswordLengthCheck باید ICollector را پیاده‌سازی کند
        var checkType = typeof(PasswordLengthCheck);
        var interfaces = checkType.GetInterfaces();

        var hasCollectorInterface = interfaces
            .Any(i => i.Name == "ICollector" || i.Name == "IEvidenceCollector");

        hasCollectorInterface.Should().BeTrue(
            "PasswordLengthCheck should implement ICollector or IEvidenceCollector interface " +
            "to declare its collector-only responsibility.");
    }

    [Fact]
    public void BaseHardeningCheck_ShouldHaveAbstractCollectMethod()
    {
        // BaseHardeningCheck باید متد abstract CollectEvidenceAsync داشته باشد
        var baseType = typeof(BaseHardeningCheck);
        var collectMethod = baseType.GetMethod("CollectEvidenceAsync");

        collectMethod.Should().NotBeNull(
            "BaseHardeningCheck should declare CollectEvidenceAsync() method");

        if (collectMethod != null)
        {
            collectMethod.IsAbstract.Should().BeTrue(
                "CollectEvidenceAsync() should be abstract to force concrete checks to implement it");

            collectMethod.ReturnType.Should().Be(typeof(Task<List<Evidence>>),
                "CollectEvidenceAsync() should return Task<List<Evidence>>, not Task<SubControlResult>");
        }
    }
}