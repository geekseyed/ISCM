using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class FailureClassificationTests
{
    // H-02.6.1 — same type, different severities: allowed (independence)
    [Fact]
    public void SameType_DifferentSeverities_BothAccepted()
    {
        var low = FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Low);
        var critical = FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Critical);

        low.Type.Should().Be(critical.Type);
        low.Severity.Should().NotBe(critical.Severity);
    }

    // H-02.6.1 — same severity, different types: allowed
    [Fact]
    public void SameSeverity_DifferentTypes_BothAccepted()
    {
        var a = FailureClassification.Create(FailureType.TestFailure, FailureSeverity.High);
        var b = FailureClassification.Create(FailureType.InfrastructureFailure, FailureSeverity.High);

        a.Severity.Should().Be(b.Severity);
        a.Type.Should().NotBe(b.Type);
    }

    // H-02.6.2 — confidence independent of severity
    [Fact]
    public void Confidence_IndependentOfSeverity()
    {
        var highSeverityLowConfidence = FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Critical, confidence: 0.1);
        var lowSeverityHighConfidence = FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Low, confidence: 0.9);

        highSeverityLowConfidence.Severity.Should().Be(FailureSeverity.Critical);
        highSeverityLowConfidence.Confidence.Should().Be(0.1);
        lowSeverityHighConfidence.Severity.Should().Be(FailureSeverity.Low);
        lowSeverityHighConfidence.Confidence.Should().Be(0.9);
    }

    // H-02.6.2 — bounds inclusive
    [Fact]
    public void Confidence_ZeroAndOne_Accepted()
    {
        FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Low, confidence: 0.0)
            .Confidence.Should().Be(0.0);
        FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Low, confidence: 1.0)
            .Confidence.Should().Be(1.0);
    }

    [Theory]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    public void Confidence_OutOfBounds_Throws(double confidence)
    {
        Action act = () => FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Low, confidence: confidence);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    // H-02.6.3 — confidence independent of uncertainty (applicability)
    [Fact]
    public void Confidence_UnknownApplicability_Allowed()
    {
        var classification = FailureClassification.Create(
            FailureType.Unknown, FailureSeverity.Unknown,
            confidence: 0.4, applicability: EvidenceState.Unknown);

        classification.Applicability.Should().Be(EvidenceState.Unknown);
        classification.Confidence.Should().Be(0.4);
    }

    // H-01.4.9 — NotApplicable cannot carry a real severity
    [Fact]
    public void NotApplicable_WithRealSeverity_Throws()
    {
        Action act = () => FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.High,
            applicability: EvidenceState.NotApplicable);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*NotApplicable*");
    }

    // H-01.4.9 — NotApplicable cannot carry confidence
    [Fact]
    public void NotApplicable_WithConfidence_Throws()
    {
        Action act = () => FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Unknown,
            confidence: 0.5, applicability: EvidenceState.NotApplicable);
        act.Should().Throw<ArgumentException>();
    }

    // H-01.4.9 — the only legal NotApplicable shape
    [Fact]
    public void NotApplicable_UnknownSeverity_NoConfidence_Accepted()
    {
        var classification = FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Unknown,
            applicability: EvidenceState.NotApplicable);

        classification.Applicability.Should().Be(EvidenceState.NotApplicable);
        classification.Severity.Should().Be(FailureSeverity.Unknown);
        classification.Confidence.Should().BeNull();
    }

    // Process states belong to ServiceResult (H-01.8), not to a record
    [Theory]
    [InlineData(EvidenceState.Missing)]
    [InlineData(EvidenceState.Derived)]
    [InlineData(EvidenceState.Unavailable)]
    [InlineData(EvidenceState.Corrupt)]
    public void ProcessStates_Refused(EvidenceState state)
    {
        Action act = () => FailureClassification.Create(
            FailureType.TestFailure, FailureSeverity.Low, applicability: state);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*ServiceResult*");
    }

    // Rank — total order for downstream ranking (feeds H-09)
    [Fact]
    public void SeverityRank_TotalOrder()
    {
        FailureSeverityRank.Of(FailureSeverity.Unknown).Should()
            .BeLessThan(FailureSeverityRank.Of(FailureSeverity.Informational));
        FailureSeverityRank.Of(FailureSeverity.Informational).Should()
            .BeLessThan(FailureSeverityRank.Of(FailureSeverity.Low));
        FailureSeverityRank.Of(FailureSeverity.Low).Should()
            .BeLessThan(FailureSeverityRank.Of(FailureSeverity.Medium));
        FailureSeverityRank.Of(FailureSeverity.Medium).Should()
            .BeLessThan(FailureSeverityRank.Of(FailureSeverity.High));
        FailureSeverityRank.Of(FailureSeverity.High).Should()
            .BeLessThan(FailureSeverityRank.Of(FailureSeverity.Critical));
    }

    [Fact]
    public void SeverityRank_IsAtLeast_ThresholdCheck()
    {
        FailureSeverityRank.IsAtLeast(FailureSeverity.High, FailureSeverity.Medium).Should().BeTrue();
        FailureSeverityRank.IsAtLeast(FailureSeverity.Low, FailureSeverity.Medium).Should().BeFalse();
        FailureSeverityRank.IsAtLeast(FailureSeverity.Unknown, FailureSeverity.Unknown).Should().BeTrue();
    }

    // Partial knowledge — Unknown type with a real severity is legal
    // (the failure happened; its kind is unclear, impact is clear)
    [Fact]
    public void UnknownType_WithSeverity_PartialKnowledgeAllowed()
    {
        var classification = FailureClassification.Create(
            FailureType.Unknown, FailureSeverity.Critical);

        classification.Type.Should().Be(FailureType.Unknown);
        classification.Severity.Should().Be(FailureSeverity.Critical);
        classification.Applicability.Should().Be(EvidenceState.Observed);
    }

    // Default applicability is Observed (a real classified failure)
    [Fact]
    public void Create_DefaultApplicability_IsObserved()
    {
        FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Low)
            .Applicability.Should().Be(EvidenceState.Observed);
    }

    // X-004 — Unknown severity is Unknown, not "zero impact"
    [Fact]
    public void UnknownSeverity_IsNotZeroImpact()
    {
        var unassessed = FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Unknown);
        var informational = FailureClassification.Create(FailureType.TestFailure, FailureSeverity.Informational);

        unassessed.Severity.Should().NotBe(informational.Severity);
        FailureSeverityRank.Of(unassessed.Severity)
            .Should().BeLessThan(FailureSeverityRank.Of(informational.Severity));
    }
}