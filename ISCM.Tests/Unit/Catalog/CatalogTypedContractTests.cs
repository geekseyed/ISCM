using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Xunit;
using FluentAssertions;
using System.Text.RegularExpressions;

namespace ISCM.Tests.Unit.Catalog;

/// <summary>
/// Golden tests for Phase 10.2 — Typed Catalog Contract
/// 
/// این تست‌ها تضمین می‌کنند که هر SubControl در کاتالوگ،
/// `ExpectedValueType` و `Operator` معناداری متناسب با متن ExpectedValue دارد.
/// </summary>
public class CatalogTypedContractTests
{
    private static readonly List<SubControlDefinition> BaselineSubControls =
        ControlCatalog.GetAll()
            .Where(c => c.IsBaseline)
            .SelectMany(c => c.SubControls ?? new List<SubControlDefinition>())
            .Where(s => s.IsRequired && !string.IsNullOrWhiteSpace(s.ExpectedValue))
            .ToList();

    /// <summary>
    /// SubControls whose ExpectedValue text contains numeric keywords
    /// but whose actual semantic is NOT a numeric threshold (e.g., "SMB1Protocol").
    /// These are explicitly exempt from the numeric-threshold test.
    /// </summary>
    private static readonly HashSet<string> NumericThresholdExemptions = new()
    {
        "SMB-001.1" // Contains "SMB1Protocol" — the "1" is part of the protocol name, not a threshold
    };

    /// <summary>
    /// SubControls whose ExpectedValue contains commas in explanatory text
    /// (e.g., "for example, 2") rather than as list separators.
    /// </summary>
    private static readonly HashSet<string> CommaListExemptions = new()
    {
        "RDP-001.5" // "Configured (for example, 2)" — comma is explanatory, value is integer 2
    };

    [Fact]
    public void BaselineSubControls_WithBooleanExpectedValue_MustHaveBooleanType()
    {
        var booleanPatterns = new[] { "Enabled", "Disabled", "On", "Off", "Yes", "No" };

        var violations = BaselineSubControls
            .Where(s => booleanPatterns.Any(p =>
                Regex.IsMatch(s.ExpectedValue, $@"\b{p}\b", RegexOptions.IgnoreCase)))
            .Where(s => s.ExpectedValueType != ExpectedValueType.Boolean &&
                        s.ExpectedValueType != ExpectedValueType.Enum)
            .Select(s => new { s.SubControlId, s.ExpectedValue, s.ExpectedValueType })
            .ToList();

        violations.Should().BeEmpty(
            $"baseline SubControls with boolean-like ExpectedValue must use Boolean/Enum. " +
            $"Violations: {string.Join(", ", violations.Select(v => $"{v.SubControlId}='{v.ExpectedValue}' (was {v.ExpectedValueType})"))}");
    }

    [Fact]
    public void BaselineSubControls_WithDurationExpectedValue_MustHaveDurationOrIntegerType()
    {
        var durationPatterns = new[] { "day", "days", "minute", "minutes", "second", "seconds" };

        var violations = BaselineSubControls
            .Where(s => durationPatterns.Any(p =>
                Regex.IsMatch(s.ExpectedValue, $@"\b{p}\b", RegexOptions.IgnoreCase)))
            .Where(s => s.ExpectedValueType != ExpectedValueType.Duration &&
                        s.ExpectedValueType != ExpectedValueType.Integer)
            .Select(s => new { s.SubControlId, s.ExpectedValue, s.ExpectedValueType })
            .ToList();

        violations.Should().BeEmpty(
            $"baseline SubControls with duration-like ExpectedValue must use Duration/Integer. " +
            $"Violations: {string.Join(", ", violations.Select(v => $"{v.SubControlId}='{v.ExpectedValue}' (was {v.ExpectedValueType})"))}");
    }

    [Fact]
    public void BaselineSubControls_WithNumericThreshold_MustUseIntegerType()
    {
        var numericPatterns = new[] { "characters", "KB", "MB", "passwords remembered", "attempts" };

        var violations = BaselineSubControls
            .Where(s => !NumericThresholdExemptions.Contains(s.SubControlId))
            .Where(s => numericPatterns.Any(p =>
                s.ExpectedValue.Contains(p, StringComparison.OrdinalIgnoreCase)) &&
                Regex.IsMatch(s.ExpectedValue, @"\d"))
            .Where(s => s.ExpectedValueType != ExpectedValueType.Integer)
            .Select(s => new { s.SubControlId, s.ExpectedValue, s.ExpectedValueType })
            .ToList();

        violations.Should().BeEmpty(
            $"baseline SubControls with numeric threshold must use Integer. " +
            $"Violations: {string.Join(", ", violations.Select(v => $"{v.SubControlId}='{v.ExpectedValue}' (was {v.ExpectedValueType})"))}");
    }

    [Fact]
    public void BaselineSubControls_WithCommaList_MustPreferCollectionOrEnumType()
    {
        var violations = BaselineSubControls
            .Where(s => !CommaListExemptions.Contains(s.SubControlId))
            .Where(s => s.ExpectedValue.Contains(","))
            .Where(s => s.ExpectedValueType != ExpectedValueType.Collection &&
                        s.ExpectedValueType != ExpectedValueType.Enum &&
                        s.ExpectedValueType != ExpectedValueType.String)
            .Select(s => new { s.SubControlId, s.ExpectedValue, s.ExpectedValueType })
            .ToList();

        violations.Should().BeEmpty(
            $"baseline SubControls with comma-lists should use Collection/Enum/String. " +
            $"Violations: {string.Join(", ", violations.Select(v => $"{v.SubControlId}='{v.ExpectedValue}' (was {v.ExpectedValueType})"))}");
    }

    [Fact]
    public void NumericThresholdSubControls_ShouldNotAllUseEqualsOperator()
    {
        var numericSubControls = BaselineSubControls
            .Where(s => s.ExpectedValueType == ExpectedValueType.Integer ||
                        s.ExpectedValueType == ExpectedValueType.Duration)
            .ToList();

        if (numericSubControls.Count == 0)
        {
            Assert.Fail("No numeric SubControls found. Run Phase 10.2.2 first to populate ExpectedValueType.");
            return;
        }

        var allEquals = numericSubControls.All(s => s.Operator == Operator.Equals);

        allEquals.Should().BeFalse(
            "not all numeric/duration SubControls should use Equals; " +
            "most thresholds should use GreaterOrEqual/LessOrEqual");
    }

    [Fact]
    public void Catalog_MustHaveMeaningfulTypedSubControls()
    {
        var typedCount = BaselineSubControls
            .Count(s => s.ExpectedValueType != ExpectedValueType.String);

        typedCount.Should().BeGreaterThan(50,
            "the catalog must have a meaningful number of typed SubControls " +
            "(not everything should default to String)");
    }
}