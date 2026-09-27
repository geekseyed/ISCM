using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class OutcomeStateTests
{
    // H-01.4.8 — zero is a REAL measured value, never "missing"
    // (KBF-08-003 / KBF-12-008 pattern)
    [Fact]
    public void Measured_ObservedZero_IsRealZeroNotMissing()
    {
        var m = Measured<int>.Observed(0);

        m.State.Should().Be(EvidenceState.Observed);
        m.HasValue.Should().BeTrue();
        m.Value.Should().Be(0);
        m.TryGet(out var v).Should().BeTrue();
        v.Should().Be(0);
    }

    // H-01.4.8 — missing carries no value; fallback is EXPLICIT
    [Fact]
    public void Measured_Missing_HasNoValueAndExplicitFallback()
    {
        var m = Measured<int>.Missing();

        m.State.Should().Be(EvidenceState.Missing);
        m.HasValue.Should().BeFalse();
        m.TryGet(out _).Should().BeFalse();
        m.ValueOr(42).Should().Be(42);   // caller sees and chooses the default
    }

    [Fact]
    public void Measured_ZeroAndMissing_AreDistinctStates()
    {
        var zero = Measured<int>.Observed(0);
        var missing = Measured<int>.Missing();

        zero.State.Should().NotBe(missing.State);
        zero.HasValue.Should().NotBe(missing.HasValue);
    }

    // H-01.4.7 — empty result is a real observation; "not measured" is not
    // (KBF-11-006 pattern: placeholder empty list != honest unavailability)
    [Fact]
    public void Measured_EmptyCollection_IsObserved_NotUnavailable()
    {
        var empty = Measured<string[]>.Observed(Array.Empty<string>());
        var notMeasured = Measured<string[]>.Unavailable("collector did not run");

        empty.HasValue.Should().BeTrue();
        empty.State.Should().Be(EvidenceState.Observed);
        notMeasured.State.Should().Be(EvidenceState.Unavailable);
        notMeasured.HasValue.Should().BeFalse();
        notMeasured.Reason.Should().Be("collector did not run");
    }

    // H-01.4.6 — asked-and-indeterminate vs never-asked
    [Fact]
    public void Measured_UnknownAndUnavailable_AreDistinct()
    {
        var unknown = Measured<bool>.Unknown();
        var unavailable = Measured<bool>.Unavailable();

        unknown.State.Should().Be(EvidenceState.Unknown);
        unavailable.State.Should().Be(EvidenceState.Unavailable);
        unknown.State.Should().NotBe(unavailable.State);
        unknown.HasValue.Should().BeFalse();
        unavailable.HasValue.Should().BeFalse();
    }

    // H-01.4.10 — corruption evidence is mandatory
    [Fact]
    public void Measured_Corrupt_RequiresNonEmptyReason()
    {
        Action noReason = () => Measured<string>.Corrupt("  ");
        var corrupt = Measured<string>.Corrupt("malformed JSON at offset 12");

        noReason.Should().Throw<ArgumentException>();
        corrupt.State.Should().Be(EvidenceState.Corrupt);
        corrupt.Reason.Should().Contain("malformed JSON");
        corrupt.HasValue.Should().BeFalse();
    }

    // H-01.4.8 — Observed(null) is the banned fabrication path
    [Fact]
    public void Measured_ObservedNull_Throws()
    {
        Action observedNull = () => Measured<string>.Observed(null!);
        observedNull.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Measured_TryGet_And_ValueOr()
    {
        var observed = Measured<string>.Observed("real");
        var missing = Measured<string>.Missing();

        observed.TryGet(out var v).Should().BeTrue();
        v.Should().Be("real");
        missing.TryGet(out _).Should().BeFalse();
        missing.ValueOr("explicit-default").Should().Be("explicit-default");
        observed.ValueOr("ignored").Should().Be("real");
    }

    // H-01.4.2 — projection from existing BF-01 vocabulary (Unknown preserved)
    [Theory]
    [InlineData(TestOutcome.Passed, TestSemanticStatus.Passed)]
    [InlineData(TestOutcome.Failed, TestSemanticStatus.Failed)]
    [InlineData(TestOutcome.Skipped, TestSemanticStatus.Skipped)]
    [InlineData(TestOutcome.Unknown, TestSemanticStatus.Unknown)]
    public void TestSemanticStatus_ProjectsFromTestOutcome(
        TestOutcome outcome, TestSemanticStatus expected)
    {
        TestSemanticStatusProjection.From(outcome).Should().Be(expected);
    }

    // H-01.4.1 — vocabulary covers all process truths (exit-code taxonomy)
    [Fact]
    public void ExecutionStatus_VocabularyCoversProcessTruths()
    {
        Enum.GetNames<ExecutionStatus>().Should().BeEquivalentTo(new[]
        {
            "NotStarted", "Executed", "BuildFailed", "DiscoveryFailed",
            "TestHostFailed", "Cancelled", "Timeout", "Unavailable"
        });
    }

    // H-01.4.3 + 1.4.9 — first-class failure semantics over CheckStatus
    [Theory]
    [InlineData(CheckStatus.Fail, true)]
    [InlineData(CheckStatus.Error, true)]
    [InlineData(CheckStatus.Unknown, false)]
    [InlineData(CheckStatus.Disagreement, false)]
    [InlineData(CheckStatus.NotApplicable, false)]
    [InlineData(CheckStatus.Ignored, false)]
    [InlineData(CheckStatus.FalsePositive, false)]
    [InlineData(CheckStatus.Unsupported, false)]
    [InlineData(CheckStatus.NotScanned, false)]
    [InlineData(CheckStatus.Pass, false)]
    public void DomainEvaluation_FirstClassFailure_Semantics(
        CheckStatus status, bool expected)
    {
        DomainEvaluationSemantics.IsFirstClassFailure(status).Should().Be(expected);
    }

    // KBF-02-002 — Disagreement/Unknown must survive as uncertainty events
    [Fact]
    public void DomainEvaluation_UncertaintyEvents_Survive()
    {
        DomainEvaluationSemantics.IsUncertaintyEvent(CheckStatus.Unknown).Should().BeTrue();
        DomainEvaluationSemantics.IsUncertaintyEvent(CheckStatus.Disagreement).Should().BeTrue();
        DomainEvaluationSemantics.IsUncertaintyEvent(CheckStatus.Fail).Should().BeFalse();
        DomainEvaluationSemantics.IsUncertaintyEvent(CheckStatus.NotApplicable).Should().BeFalse();
    }

    // H-01.4.9 — the exclusion family can never become a failure
    [Fact]
    public void DomainEvaluation_NotApplicableFamily_NeverFailure()
    {
        foreach (var status in new[]
                 {
                     CheckStatus.NotApplicable, CheckStatus.Ignored,
                     CheckStatus.FalsePositive, CheckStatus.Unsupported
                 })
        {
            DomainEvaluationSemantics.IsFirstClassFailure(status).Should().BeFalse(
                $"{status} must never be reported as a failure (H-01.4.9)");
            DomainEvaluationSemantics.IsNotApplicableFamily(status).Should().BeTrue();
        }
    }

    // Knowledge provenance for all ten domain statuses
    [Theory]
    [InlineData(CheckStatus.Pass, EvidenceState.Observed)]
    [InlineData(CheckStatus.Fail, EvidenceState.Observed)]
    [InlineData(CheckStatus.Error, EvidenceState.Observed)]
    [InlineData(CheckStatus.Unknown, EvidenceState.Unknown)]
    [InlineData(CheckStatus.Disagreement, EvidenceState.Unknown)]
    [InlineData(CheckStatus.NotScanned, EvidenceState.Unavailable)]
    [InlineData(CheckStatus.Unsupported, EvidenceState.Unavailable)]
    [InlineData(CheckStatus.NotApplicable, EvidenceState.NotApplicable)]
    [InlineData(CheckStatus.Ignored, EvidenceState.NotApplicable)]
    [InlineData(CheckStatus.FalsePositive, EvidenceState.NotApplicable)]
    public void DomainEvaluation_ToEvidenceState_AllTenStatuses(
        CheckStatus status, EvidenceState expected)
    {
        DomainEvaluationSemantics.ToEvidenceState(status).Should().Be(expected);
    }

    // H-01.4.4 — infrastructure vs application-defect separation (KBF-02-006)
    [Fact]
    public void FailureSemantics_InfrastructureVsApplicationDefect()
    {
        FailureSemantics.IsInfrastructureOrigin(FailureType.InfrastructureFailure).Should().BeTrue();
        FailureSemantics.IsInfrastructureOrigin(FailureType.TimeoutFailure).Should().BeTrue();
        FailureSemantics.IsApplicationDefectCandidate(FailureType.TestFailure).Should().BeTrue();
        FailureSemantics.IsApplicationDefectCandidate(FailureType.DomainEvaluationFailure).Should().BeTrue();
        FailureSemantics.IsApplicationDefectCandidate(FailureType.ExceptionFailure).Should().BeTrue();
        FailureSemantics.IsApplicationDefectCandidate(FailureType.InfrastructureFailure).Should().BeFalse();
        FailureSemantics.IsComposite(FailureType.CompositeFailure).Should().BeTrue();
    }

    // Core principle — detected failures are OBSERVED facts; only Unknown is Unknown
    [Theory]
    [InlineData(FailureType.TestFailure, EvidenceState.Observed)]
    [InlineData(FailureType.DomainEvaluationFailure, EvidenceState.Observed)]
    [InlineData(FailureType.ExceptionFailure, EvidenceState.Observed)]
    [InlineData(FailureType.TimeoutFailure, EvidenceState.Observed)]
    [InlineData(FailureType.InfrastructureFailure, EvidenceState.Observed)]
    [InlineData(FailureType.CompositeFailure, EvidenceState.Observed)]
    [InlineData(FailureType.Unknown, EvidenceState.Unknown)]
    public void FailureSemantics_DetectedFailuresAreObserved(
        FailureType type, EvidenceState expected)
    {
        FailureSemantics.ToEvidenceState(type).Should().Be(expected);
    }

    // H-01.4.5 — uncertainty reporting matrix
    [Theory]
    [InlineData(EvidenceState.Observed, false)]
    [InlineData(EvidenceState.Derived, false)]
    [InlineData(EvidenceState.NotApplicable, false)]
    [InlineData(EvidenceState.Missing, true)]
    [InlineData(EvidenceState.Unknown, true)]
    [InlineData(EvidenceState.Unavailable, true)]
    [InlineData(EvidenceState.Corrupt, true)]
    public void UncertaintySemantics_RequiresReporting_Matrix(
        EvidenceState state, bool expected)
    {
        UncertaintySemantics.RequiresUncertaintyReporting(state).Should().Be(expected);
    }
}