using ISCM.Application.Evaluators;
using ISCM.Application.Services;
using ISCM.Application.Evaluators.Typed;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Unit.Evaluators;

/// <summary>
/// تست‌های واحد برای TypedEvidenceEvaluator
/// 
/// این تست‌ها تأیید می‌کنند که dispatcher به درستی:
/// 1. انواع مختلف را به evaluator مربوطه route می‌کند
/// 2. خطاهای نوع (TypeMismatch) را به درستی مدیریت می‌کند
/// 3. حالت‌های null و خالی را مدیریت می‌کند
/// </summary>
public class TypedEvidenceEvaluatorTests
{
    private readonly TypedEvidenceEvaluator _evaluator;

    public TypedEvidenceEvaluatorTests()
    {
        var parser = new ExpectedValueParser();
        var intEval = new IntegerEvaluator();
        var longEval = new LongEvaluator();
        var boolEval = new BooleanEvaluator();
        var strEval = new StringEvaluator();
        var durEval = new DurationEvaluator();
        var sizeEval = new SizeEvaluator();
        var enumEval = new EnumEvaluator();
        var collEval = new CollectionEvaluator();
        var regEval = new RegistryValueEvaluator();
        var policyEval = new PolicyValueEvaluator();

        _evaluator = new TypedEvidenceEvaluator(
            parser,
            intEval,
            longEval,
            boolEval,
            strEval,
            durEval,
            sizeEval,
            enumEval,
            collEval,
            regEval,
            policyEval);
    }

    [Fact]
    public void Evaluate_WithNullEvidenceValue_ReturnsError()
    {
        // Act
        var result = _evaluator.Evaluate(
            (EvidenceValue)null!,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.Should().NotBeNull();
        result.IsError.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_WithNullTypedValue_ReturnsError()
    {
        // Arrange
        var evidenceValue = new EvidenceValue
        {
            TypedValue = null,
            ValueType = EvidenceValueType.Unknown
        };

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.IsError.Should().BeTrue();
        result.Reason.Should().Contain("TypedValue is null");
    }

    [Fact]
    public void Evaluate_Integer_Equals_ReturnsPass_WhenMatch()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromInteger(42);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "42",
            ExpectedValueType.Integer,
            Operator.Equals);

        // Assert
        result.IsPass.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Integer_GreaterOrEqual_ReturnsPass_WhenActualIsGreater()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromInteger(50);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "14 characters",
            ExpectedValueType.Integer,
            Operator.GreaterOrEqual);

        // Assert
        result.IsPass.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Integer_GreaterOrEqual_ReturnsFail_WhenActualIsLess()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromInteger(10);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "14 characters",
            ExpectedValueType.Integer,
            Operator.GreaterOrEqual);

        // Assert
        result.IsFail.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Boolean_Equals_ReturnsPass_WhenMatch()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromBoolean(true);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "Enabled",
            ExpectedValueType.Boolean,
            Operator.Equals);

        // Assert
        result.IsPass.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Boolean_Equals_ReturnsFail_WhenMismatch()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromBoolean(true);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "Disabled",
            ExpectedValueType.Boolean,
            Operator.Equals);

        // Assert
        result.IsFail.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Duration_LessOrEqual_ReturnsPass_WhenActualIsLess()
    {
        // Arrange - 30 days
        var evidenceValue = EvidenceValue.FromDuration(
            new DurationValue(30, DurationUnit.Days));

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "60 days",
            ExpectedValueType.Duration,
            Operator.LessOrEqual);

        // Assert
        result.IsPass.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_Duration_LessOrEqual_ReturnsFail_WhenActualIsGreater()
    {
        // Arrange - 90 days
        var evidenceValue = EvidenceValue.FromDuration(
            new DurationValue(90, DurationUnit.Days));

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "60 days",
            ExpectedValueType.Duration,
            Operator.LessOrEqual);

        // Assert
        result.IsFail.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_String_Contains_ReturnsPass_WhenSubstringExists()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromString("This is a test string");

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "test",
            ExpectedValueType.String,
            Operator.Contains);

        // Assert
        result.IsPass.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_WithTypeMismatch_ReturnsError()
    {
        // Arrange - actual is string, expected is Integer
        var evidenceValue = EvidenceValue.FromString("not a number");

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "42",
            ExpectedValueType.Integer,
            Operator.Equals);

        // Assert
        result.IsError.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_WithInvalidExpectedValue_ReturnsError()
    {
        // Arrange
        var evidenceValue = EvidenceValue.FromInteger(42);

        // Act
        var result = _evaluator.Evaluate(
            evidenceValue,
            "not a number",
            ExpectedValueType.Integer,
            Operator.Equals);

        // Assert
        result.IsError.Should().BeTrue();
    }

    [Fact]
    public void Evaluate_WithEntity_ExtractsTypedValue()
    {
        // Arrange
        var evidence = new Evidence
        {
            TypedValue = EvidenceValue.FromInteger(42),
            RawOutput = "42"
        };

        // Act
        var result = _evaluator.Evaluate(
            evidence,
            "42",
            ExpectedValueType.Integer,
            Operator.Equals);

        // Assert
        result.IsPass.Should().BeTrue();
    }
}