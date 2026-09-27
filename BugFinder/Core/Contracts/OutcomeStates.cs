using System.Diagnostics.CodeAnalysis;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.4: Outcome State Contract (audit X-004: zero / empty / null /
/// unavailable / unknown used interchangeably).
///
/// CORE PRINCIPLE: EvidenceState describes HOW WE KNOW (knowledge
/// provenance), never outcome polarity. A detected failure is an
/// OBSERVED fact; "bad" and "absent" must never merge.
///
///   H-01.4.1  ExecutionStatus        - process-level truth (adopted by H-03;
///                                      fixes KBF-01-001 fabricated exit code)
///   H-01.4.2  TestSemanticStatus     - canonical test semantics + projection
///                                      from TestOutcome
///   H-01.4.3  DomainEvaluationSemantics - CheckStatus interpretation; fixes
///                                      KBF-02-002 (only Fail became a failure)
///   H-01.4.4  FailureSemantics       - FailureType projection; seeds
///                                      KBF-02-006 infrastructure separation
///   H-01.4.5  UncertaintySemantics   - when uncertainty MUST be reported
///   H-01.4.6  Unknown != Unavailable (asked-and-indeterminate vs never-asked)
///   H-01.4.7  Empty != NotMeasured   (Observed(empty) vs Unavailable)
///   H-01.4.8  Zero != Missing        (Measured.Observed(0) vs Missing();
///                                      fixes KBF-08-003 / KBF-12-008)
///   H-01.4.9  NotApplicable != Failure
///   H-01.4.10 CorruptArtifact        - reached but unreadable; reason mandatory
///
/// ADOPTION: existing enums (TestOutcome / CheckStatus / FailureType)
/// remain authoritative for their layers; the projections here define
/// cross-layer semantics. Service adoption (real exit code, real metrics)
/// lands in H-03+.
/// </summary>
public enum EvidenceState
{
    /// <summary>Recorded from a real source. Zero and empty are valid observed values.</summary>
    Observed,

    /// <summary>Computed from other evidence; provenance required (H-08.7).</summary>
    Derived,

    /// <summary>Expected in the artifact but absent (1.4.8: NOT zero).</summary>
    Missing,

    /// <summary>Source consulted; answer indeterminate (1.4.6: != Unavailable).</summary>
    Unknown,

    /// <summary>Source itself not reachable/collected (1.4.7: NotMeasured).</summary>
    Unavailable,

    /// <summary>Source reached but artifact unreadable / integrity failed (1.4.10).</summary>
    Corrupt,

    /// <summary>Concept does not apply to this context (1.4.9: never a failure).</summary>
    NotApplicable
}

/// <summary>
/// Value + state container (H-01.4.7/1.4.8): carries the distinction
/// between a real measured value (zero / empty are REAL) and absence
/// of measurement. The only honest way to hand a "count" downstream.
/// </summary>
public sealed class Measured<T>
{
    public EvidenceState State { get; }
    public T? Value { get; }

    /// <summary>Corruption / unavailability evidence (mandatory for Corrupt).</summary>
    public string? Reason { get; }

    private Measured(EvidenceState state, T? value, string? reason)
        => (State, Value, Reason) = (state, value, reason);

    /// <summary>A real measured value - including zero and empty (H-01.4.8).</summary>
    public static Measured<T> Observed(T value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value),
                "Observed requires a real value; use Missing()/Unavailable() when there is none (Zero != Missing, H-01.4.8).");
        return new Measured<T>(EvidenceState.Observed, value, null);
    }

    /// <summary>Computed from other evidence (provenance is the caller's duty, H-08.7).</summary>
    public static Measured<T> Derived(T value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value),
                "Derived requires a computed value; use Missing()/Unavailable() when there is none.");
        return new Measured<T>(EvidenceState.Derived, value, null);
    }

    /// <summary>Expected but absent (H-01.4.8: this is NOT zero).</summary>
    public static Measured<T> Missing() => new(EvidenceState.Missing, default, null);

    /// <summary>Consulted, indeterminate (H-01.4.6: this is NOT Unavailable).</summary>
    public static Measured<T> Unknown() => new(EvidenceState.Unknown, default, null);

    /// <summary>Source not reachable / not collected (H-01.4.7: this is NOT an empty result).</summary>
    public static Measured<T> Unavailable(string? reason = null) =>
        new(EvidenceState.Unavailable, default, reason);

    /// <summary>Reached but unreadable; corruption evidence is mandatory (H-01.4.10, H-06.4.4).</summary>
    public static Measured<T> Corrupt(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException(
                "Corrupt state requires a reason - corruption evidence must be preserved (H-06.4.4).",
                nameof(reason));
        return new Measured<T>(EvidenceState.Corrupt, default, reason);
    }

    /// <summary>Concept does not apply (H-01.4.9: never a failure).</summary>
    public static Measured<T> NotApplicable() => new(EvidenceState.NotApplicable, default, null);

    /// <summary>True only for Observed/Derived - the only states allowed to carry a value.</summary>
    public bool HasValue => State is EvidenceState.Observed or EvidenceState.Derived;

    public bool TryGet([NotNullWhen(true)] out T? value)
    {
        value = HasValue ? Value : default;
        return HasValue;
    }

    /// <summary>EXPLICIT fallback - the caller must see and choose the default
    /// (the anti-pattern this contract bans: silent zero on missing data).</summary>
    public T ValueOr(T fallback) => HasValue ? Value! : fallback;
}

/// <summary>
/// H-01.4.1: process-level execution truth. Test failure is distinct from
/// infrastructure failure; a real exit code is captured and classified
/// (adoption + fabrication fix in H-03, audit KBF-01-001).
/// </summary>
public enum ExecutionStatus
{
    NotStarted,
    /// <summary>Process ran to completion; real exit code captured and classified.</summary>
    Executed,
    BuildFailed,
    DiscoveryFailed,
    TestHostFailed,
    /// <summary>Observed cancellation; child process terminated deterministically (H-03.3).</summary>
    Cancelled,
    Timeout,
    /// <summary>Process could not be launched at all (1.4.6: Unavailable, not Unknown).</summary>
    Unavailable
}

/// <summary>
/// H-01.4.2: canonical test-level semantics. Unknown is preserved as
/// Unknown (mapping it to NotRun would fabricate "did not run" from
/// "we do not know" - audit KBF-01-011).
/// </summary>
public enum TestSemanticStatus
{
    NotRun,
    Passed,
    Failed,
    Error,
    Skipped,
    Unknown
}

/// <summary>Projection from the existing BF-01 vocabulary.</summary>
public static class TestSemanticStatusProjection
{
    public static TestSemanticStatus From(TestOutcome outcome) => outcome switch
    {
        TestOutcome.Passed => TestSemanticStatus.Passed,
        TestOutcome.Failed => TestSemanticStatus.Failed,
        TestOutcome.Skipped => TestSemanticStatus.Skipped,
        TestOutcome.Unknown => TestSemanticStatus.Unknown,
        _ => TestSemanticStatus.Unknown
    };
}

/// <summary>
/// H-01.4.3 (+1.4.9): canonical interpretation of the domain CheckStatus
/// vocabulary. Fixes KBF-02-002: Error/Disagreement/Unknown are first-class
/// semantics - only NotApplicable-family statuses are excluded from failure.
/// </summary>
public static class DomainEvaluationSemantics
{
    /// <summary>Fail AND Error are first-class failure events (1.4.9: NotApplicable never is).</summary>
    public static bool IsFirstClassFailure(CheckStatus status) =>
        status is CheckStatus.Fail or CheckStatus.Error;

    /// <summary>Uncertainty events must survive into the investigation flow (KBF-02-002).</summary>
    public static bool IsUncertaintyEvent(CheckStatus status) =>
        status is CheckStatus.Unknown or CheckStatus.Disagreement;

    /// <summary>The exclusion family - never convertible into a failure.</summary>
    public static bool IsNotApplicableFamily(CheckStatus status) =>
        status is CheckStatus.NotApplicable or CheckStatus.Ignored
               or CheckStatus.FalsePositive or CheckStatus.Unsupported;

    /// <summary>Knowledge provenance per domain status (1.4.9: a Fail is OBSERVED).</summary>
    public static EvidenceState ToEvidenceState(CheckStatus status) => status switch
    {
        CheckStatus.Pass => EvidenceState.Observed,
        CheckStatus.Fail => EvidenceState.Observed,
        CheckStatus.Error => EvidenceState.Observed,
        CheckStatus.Unknown => EvidenceState.Unknown,
        CheckStatus.Disagreement => EvidenceState.Unknown,
        CheckStatus.NotScanned => EvidenceState.Unavailable,
        CheckStatus.Unsupported => EvidenceState.Unavailable,
        CheckStatus.NotApplicable => EvidenceState.NotApplicable,
        CheckStatus.Ignored => EvidenceState.NotApplicable,
        CheckStatus.FalsePositive => EvidenceState.NotApplicable,
        _ => EvidenceState.Unknown
    };
}

/// <summary>
/// H-01.4.4: failure-type projection. Seeds KBF-02-006 (infrastructure
/// separation) and KBF-02-007 (composite identity, deepened in H-02.5).
/// </summary>
public static class FailureSemantics
{
    /// <summary>Every DETECTED failure is an observed fact (state != polarity).</summary>
    public static EvidenceState ToEvidenceState(FailureType type) => type switch
    {
        FailureType.Unknown => EvidenceState.Unknown,
        _ => EvidenceState.Observed
    };

    /// <summary>Origin is infrastructure, not an application defect (KBF-02-006).</summary>
    public static bool IsInfrastructureOrigin(FailureType type) =>
        type is FailureType.InfrastructureFailure or FailureType.TimeoutFailure;

    public static bool IsApplicationDefectCandidate(FailureType type) =>
        type is FailureType.TestFailure or FailureType.DomainEvaluationFailure
             or FailureType.ExceptionFailure;

    public static bool IsComposite(FailureType type) => type == FailureType.CompositeFailure;
}

/// <summary>
/// H-01.4.5: uncertainty reporting rule - whenever knowledge is not
/// Observed/Derived/NotApplicable, uncertainty MUST be explicitly
/// reported downstream (deepened in H-09).
/// </summary>
public static class UncertaintySemantics
{
    public static bool RequiresUncertaintyReporting(EvidenceState state) =>
        state is EvidenceState.Missing or EvidenceState.Unknown
              or EvidenceState.Unavailable or EvidenceState.Corrupt;
}