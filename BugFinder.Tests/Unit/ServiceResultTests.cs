using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class ServiceResultTests
{
    // H-01.8.1 — success
    [Fact]
    public void Success_CarriesPayload_ObservedState()
    {
        var result = ServiceResult<string>.Success("payload");

        result.Kind.Should().Be(ServiceResultKind.Success);
        result.State.Should().Be(EvidenceState.Observed);
        result.HasValue.Should().BeTrue();
        result.Value.Should().Be("payload");
        result.Reasons.Should().BeEmpty();
        result.Diagnostics.Should().BeEmpty();
    }

    // H-01.8.1 — success(null) is the banned fabrication path
    [Fact]
    public void Success_NullPayload_Throws()
    {
        Action act = () => ServiceResult<string>.Success(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // H-01.8.5 — partial: payload + mandatory reasons
    [Fact]
    public void Partial_CarriesPayloadAndReasons()
    {
        var result = ServiceResult<int>.Partial(42, new[] { "coverage artifact missing" });

        result.Kind.Should().Be(ServiceResultKind.Partial);
        result.HasValue.Should().BeTrue();
        result.Value.Should().Be(42);
        result.Reasons.Should().Contain("coverage artifact missing");
    }

    [Fact]
    public void Partial_WithoutReasons_Throws()
    {
        Action noReasons = () => ServiceResult<int>.Partial(1, Array.Empty<string>());
        Action nullReasons = () => ServiceResult<int>.Partial(1, null!);
        noReasons.Should().Throw<ArgumentException>();
        nullReasons.Should().Throw<ArgumentException>();
    }

    // H-01.8.2 — failure: reasons mandatory; no payload
    [Fact]
    public void Failure_CarriesReasons_NoPayload()
    {
        var result = ServiceResult<int>.Failure("rule A violated", "rule B violated");

        result.Kind.Should().Be(ServiceResultKind.Failure);
        result.State.Should().Be(EvidenceState.Observed);   // a detected failure is a fact (H-01.4)
        result.HasValue.Should().BeFalse();
        result.Reasons.Should().HaveCount(2);
    }

    [Fact]
    public void Failure_WithoutReasons_Throws()
    {
        Action act = () => ServiceResult<int>.Failure();
        act.Should().Throw<ArgumentException>();
    }

    // H-01.8.3 — unavailable with reason + optional source
    [Fact]
    public void Unavailable_RequiresReason_RecordsSource()
    {
        var result = ServiceResult<int>.Unavailable("collector did not run", "SystemResourceMonitor");

        result.Kind.Should().Be(ServiceResultKind.Unavailable);
        result.State.Should().Be(EvidenceState.Unavailable);
        result.HasValue.Should().BeFalse();
        result.Diagnostics.Should().ContainSingle()
            .Which.Source.Should().Be("SystemResourceMonitor");
    }

    [Fact]
    public void Unavailable_WithoutReason_Throws()
    {
        Action act = () => ServiceResult<int>.Unavailable(" ");
        act.Should().Throw<ArgumentException>();
    }

    // H-01.8.4 — corrupt: reached but unreadable (anti-KBF-11-004)
    [Fact]
    public void Corrupt_RequiresReason_PreservesEvidence()
    {
        var result = ServiceResult<int>.Corrupt("malformed JSON at offset 12", "FailureHistoryService");

        result.Kind.Should().Be(ServiceResultKind.Corrupt);
        result.State.Should().Be(EvidenceState.Corrupt);
        result.HasValue.Should().BeFalse();
        result.Diagnostics.Should().ContainSingle()
            .Which.Message.Should().Contain("malformed JSON");
    }

    [Fact]
    public void Corrupt_WithoutReason_Throws()
    {
        Action act = () => ServiceResult<int>.Corrupt("");
        act.Should().Throw<ArgumentException>();
    }

    // H-01.8.6 — diagnostic error: engine bug, DISTINCT from domain failure
    [Fact]
    public void DiagnosticError_FromException_CapturesTypeNameNotObject()
    {
        var result = ServiceResult<int>.DiagnosticError(
            new InvalidOperationException("boom"), "SomeService");

        result.Kind.Should().Be(ServiceResultKind.DiagnosticError);
        result.State.Should().Be(EvidenceState.Unknown);
        result.HasValue.Should().BeFalse();
        result.Diagnostics.Should().ContainSingle(d =>
            d.ExceptionTypeName == "System.InvalidOperationException"
            && d.Message == "boom");
    }

    [Fact]
    public void DiagnosticError_FromMessage_Works()
    {
        var result = ServiceResult<int>.DiagnosticError("index out of range", "OtherService");

        result.Kind.Should().Be(ServiceResultKind.DiagnosticError);
        result.Reasons.Should().Contain(r => r.Contains("engine diagnostic error"));
    }

    [Fact]
    public void DiagnosticError_NullException_Throws()
    {
        Action act = () => ServiceResult<int>.DiagnosticError((Exception)null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // X-002 — THE distinction: engine bug != domain failure
    [Fact]
    public void DiagnosticError_And_Failure_AreDistinctKinds()
    {
        var engineBug = ServiceResult<int>.DiagnosticError("boom");
        var domainFailure = ServiceResult<int>.Failure("rule violated");

        engineBug.Kind.Should().NotBe(domainFailure.Kind);
        engineBug.State.Should().Be(EvidenceState.Unknown);
        domainFailure.State.Should().Be(EvidenceState.Observed);
    }

    // H-01.8.7 — explicit fallback + TryGetValue semantics
    [Fact]
    public void ValueOr_And_TryGetValue_Semantics()
    {
        var success = ServiceResult<string>.Success("real");
        var failure = ServiceResult<string>.Failure("nope");

        success.ValueOr("fallback").Should().Be("real");
        failure.ValueOr("fallback").Should().Be("fallback");

        success.TryGetValue(out var v1).Should().BeTrue();
        v1.Should().Be("real");
        failure.TryGetValue(out _).Should().BeFalse();
    }

    // Non-generic helpers (evidence-free results)
    [Fact]
    public void NonGeneric_Helpers_Work()
    {
        ServiceResult.Success().Kind.Should().Be(ServiceResultKind.Success);
        ServiceResult.Failure("why").Kind.Should().Be(ServiceResultKind.Failure);
        ServiceResult.Unavailable("no source").Kind.Should().Be(ServiceResultKind.Unavailable);
        ServiceResult.Corrupt("bad json").Kind.Should().Be(ServiceResultKind.Corrupt);
        ServiceResult.Partial(new[] { "gap" }).Kind.Should().Be(ServiceResultKind.Partial);
        ServiceResult.DiagnosticError(new Exception("x")).Kind.Should().Be(ServiceResultKind.DiagnosticError);
    }

    // ToString — human-readable summary
    [Fact]
    public void ToString_SummarizesKindStateAndReasons()
    {
        var result = ServiceResult<int>.Failure("r1", "r2");
        result.ToString().Should().Contain("Failure").And.Contain("r1").And.Contain("r2");

        ServiceResult<int>.Success(5).ToString().Should().Contain("[payload]");
    }

    // Round-trip sanity — diagnostics are serializable (no live exceptions)
    [Fact]
    public void Diagnostics_CarryExceptionTypeName_NotLiveObjects()
    {
        var result = ServiceResult<int>.DiagnosticError(new InvalidOperationException("x"));

        result.Diagnostics[0].ExceptionTypeName.Should().Be("System.InvalidOperationException");
        result.Diagnostics[0].Should().BeOfType<ServiceDiagnostic>();
    }
}