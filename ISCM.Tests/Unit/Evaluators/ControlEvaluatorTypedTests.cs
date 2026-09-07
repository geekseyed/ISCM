using ISCM.Application.Evaluators;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using Moq;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Unit.Evaluators;

/// <summary>
/// تست‌های واحد برای ControlEvaluator.EvaluateSubControlTyped
/// 
/// این تست‌ها تأیید می‌کنند که:
/// 1. ارزیابی تایپ‌شده به درستی از ITypedEvidenceEvaluator استفاده می‌کند
/// 2. نتیجه ارزیابی به درستی در SubControlResult.Status منعکس می‌شود
/// 3. حالت‌های خطا (null TypedValue، عدم تطابق نوع) به درستی مدیریت می‌شوند
/// </summary>
public class ControlEvaluatorTypedTests
{
    private readonly Mock<ITypedEvidenceEvaluator> _mockTypedEvaluator;
    private readonly ControlEvaluator _evaluator;

    public ControlEvaluatorTypedTests()
    {
        _mockTypedEvaluator = new Mock<ITypedEvidenceEvaluator>();
        _evaluator = new ControlEvaluator(_mockTypedEvaluator.Object);
    }

    [Fact]
    public void EvaluateSubControlTyped_WithNullTypedEvaluator_ThrowsInvalidOperationException()
    {
        // Arrange
        var evaluatorWithoutTyped = new ControlEvaluator();
        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence>
            {
                new Evidence { TypedValue = EvidenceValue.FromString("test") }
            }
        };

        // Act & Assert
        var action = () => evaluatorWithoutTyped.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*ITypedEvidenceEvaluator*");
    }

    [Fact]
    public void EvaluateSubControlTyped_WithEmptyEvidenceItems_ReturnsUnknown()
    {
        // Arrange
        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence>()
        };

        // Act
        var result = _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.AggregatedStatus.Should().Be(CheckStatus.Unknown);
        result.AggregatedReason.Should().Contain("no evidence");
        subControlResult.Status.Should().Be(CheckStatus.Unknown);
    }

    [Fact]
    public void EvaluateSubControlTyped_WithSinglePassEvidence_ReturnsPass()
    {
        // Arrange
        var evidence = new Evidence
        {
            TypedValue = EvidenceValue.FromString("test"),
            Evaluation = CheckStatus.NotScanned
        };

        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence> { evidence }
        };

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(
                evidence,
                "test",
                ExpectedValueType.String,
                Operator.Equals))
            .Returns(EvaluationResult.Pass("Value matches"));

        // Act
        var result = _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.AggregatedStatus.Should().Be(CheckStatus.Pass);
        subControlResult.Status.Should().Be(CheckStatus.Pass);
        evidence.Evaluation.Should().Be(CheckStatus.Pass);
    }

    [Fact]
    public void EvaluateSubControlTyped_WithSingleFailEvidence_ReturnsFail()
    {
        // Arrange
        var evidence = new Evidence
        {
            TypedValue = EvidenceValue.FromString("wrong"),
            Evaluation = CheckStatus.NotScanned
        };

        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence> { evidence }
        };

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(
                evidence,
                "correct",
                ExpectedValueType.String,
                Operator.Equals))
            .Returns(EvaluationResult.Fail("Value does not match"));

        // Act
        var result = _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "correct",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.AggregatedStatus.Should().Be(CheckStatus.Fail);
        subControlResult.Status.Should().Be(CheckStatus.Fail);
        evidence.Evaluation.Should().Be(CheckStatus.Fail);
    }

    [Fact]
    public void EvaluateSubControlTyped_WithMultipleEvidence_PropagatesAllResults()
    {
        // Arrange
        var evidence1 = new Evidence { TypedValue = EvidenceValue.FromString("test1") };
        var evidence2 = new Evidence { TypedValue = EvidenceValue.FromString("test2") };

        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence> { evidence1, evidence2 }
        };

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(evidence1, "test", ExpectedValueType.String, Operator.Equals))
            .Returns(EvaluationResult.Pass("Pass 1"));

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(evidence2, "test", ExpectedValueType.String, Operator.Equals))
            .Returns(EvaluationResult.Pass("Pass 2"));

        // Act
        var result = _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.AggregatedStatus.Should().Be(CheckStatus.Pass);
        result.PerEvidenceResults.Should().HaveCount(2);
        evidence1.Evaluation.Should().Be(CheckStatus.Pass);
        evidence2.Evaluation.Should().Be(CheckStatus.Pass);
    }

    [Theory]
    [InlineData(CheckStatus.Error, CheckStatus.Pass, CheckStatus.Error)]
    [InlineData(CheckStatus.Unknown, CheckStatus.Pass, CheckStatus.Unknown)]
    [InlineData(CheckStatus.Fail, CheckStatus.Pass, CheckStatus.Fail)]
    public void EvaluateSubControlTyped_FollowsPrecedenceRules(
        CheckStatus firstStatus,
        CheckStatus secondStatus,
        CheckStatus expectedAggregated)
    {
        // Arrange
        var evidence1 = new Evidence { TypedValue = EvidenceValue.FromString("test1") };
        var evidence2 = new Evidence { TypedValue = EvidenceValue.FromString("test2") };

        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence> { evidence1, evidence2 }
        };

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(evidence1, It.IsAny<string>(), It.IsAny<ExpectedValueType>(), It.IsAny<Operator>()))
            .Returns(CreateResult(firstStatus));

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(evidence2, It.IsAny<string>(), It.IsAny<ExpectedValueType>(), It.IsAny<Operator>()))
            .Returns(CreateResult(secondStatus));

        // Act
        var result = _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        result.AggregatedStatus.Should().Be(expectedAggregated);

        // Helper method
        static EvaluationResult CreateResult(CheckStatus status) => status switch
        {
            CheckStatus.Pass => EvaluationResult.Pass("Pass"),
            CheckStatus.Fail => EvaluationResult.Fail("Fail"),
            CheckStatus.Error => EvaluationResult.Error("Error"),
            CheckStatus.Unknown => EvaluationResult.Unknown("Unknown"),
            _ => throw new ArgumentException($"Unexpected status: {status}")
        };
    }

    [Fact]
    public void EvaluateSubControlTyped_UpdatesEvaluatedAt()
    {
        // Arrange
        var beforeEval = DateTime.UtcNow.AddSeconds(-1);
        var evidence = new Evidence { TypedValue = EvidenceValue.FromString("test") };
        var subControlResult = new SubControlResult
        {
            SubControlId = "TEST-001",
            EvidenceItems = new List<Evidence> { evidence },
            EvaluatedAt = beforeEval
        };

        _mockTypedEvaluator
            .Setup(x => x.Evaluate(
                It.IsAny<Evidence>(),
                It.IsAny<string>(),
                It.IsAny<ExpectedValueType>(),
                It.IsAny<Operator>()))
            .Returns(EvaluationResult.Pass("Pass"));

        // Act
        _evaluator.EvaluateSubControlTyped(
            subControlResult,
            "test",
            ExpectedValueType.String,
            Operator.Equals);

        // Assert
        subControlResult.EvaluatedAt.Should().BeAfter(beforeEval);
    }
}