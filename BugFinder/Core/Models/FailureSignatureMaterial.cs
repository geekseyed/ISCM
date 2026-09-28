using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-02.1: Failure Signature Input Definition.
/// Everything KNOWN about one failure occurrence, collected raw - the
/// input from which H-02.2 derives the deterministic FailureSignature.
///
/// SECTION MAP (2.1.1-2.1.7):
///   2.1.1 Test identity      - canonical FailureIdentity (H-01.6)
///   2.1.2 Assertion identity - type + message (extraction deepens in H-03)
///   2.1.3 Exception identity - type + inner chain (type names only)
///   2.1.4 Domain failure     - SubControlId + CheckStatus
///   2.1.5 Source location    - canonical SourceLocation (H-01.6)
///   2.1.6 Message            - RAW preserved (normalized in 2.2.5)
///   2.1.7 Execution context  - environment fingerprint
///
/// CONTRACTS:
///   - No fabrication: unknown knowledge stays null/empty (H-01.4).
///   - ExecutionSessionId and OccurredAt are NOT part of the material -
///     they belong to the failure INSTANCE (H-02.3.2/2.3.5); the
///     signature must stay session-independent so cross-session
///     recurrence (H-02.4.5) can link by signature alone.
///   - Whether any section enters the final hash is H-02.2's decision.
/// </summary>
public sealed class FailureSignatureMaterial
{
    // H-02.1.1 — canonical test identity
    public FailureIdentity TestIdentity { get; init; } = new();

    // H-02.1.2 — assertion identity
    public string? AssertionType { get; init; }
    public string? AssertionMessage { get; init; }

    // H-02.1.3 — exception identity (type names only; chain order preserved)
    public string? ExceptionTypeName { get; init; }
    public IReadOnlyList<string> InnerExceptionTypeNames { get; init; } = Array.Empty<string>();

    // H-02.1.4 — domain failure identity
    public string? SubControlId { get; init; }
    public CheckStatus? DomainStatus { get; init; }

    // H-02.1.5 — canonical source location
    public SourceLocation? Location { get; init; }

    // H-02.1.6 — raw message (normalization is H-02.2.5's job)
    public string? RawMessage { get; init; }

    // H-02.1.7 — execution context
    public string? EnvironmentFingerprint { get; init; }

    /// <summary>True when at least one section carries knowledge.</summary>
    public bool HasAnyKnowledge =>
        !string.IsNullOrEmpty(TestIdentity.TestName)
        || !string.IsNullOrEmpty(TestIdentity.ClassName)
        || !string.IsNullOrEmpty(TestIdentity.AssemblyName)
        || !string.IsNullOrWhiteSpace(AssertionType)
        || !string.IsNullOrWhiteSpace(AssertionMessage)
        || !string.IsNullOrWhiteSpace(ExceptionTypeName)
        || InnerExceptionTypeNames.Count > 0
        || !string.IsNullOrWhiteSpace(SubControlId)
        || DomainStatus.HasValue
        || Location is not null
        || !string.IsNullOrWhiteSpace(RawMessage)
        || !string.IsNullOrWhiteSpace(EnvironmentFingerprint);
}

/// <summary>
/// H-02.1: adapters from existing BF-01 data into signature material.
/// Raw message is PREFERRED over processed (BF-01 GAP-01 fields); unknown
/// knowledge is never fabricated (H-01.4).
/// </summary>
public static class FailureSignatureMaterialFactory
{
    /// <summary>Material from a normalized TEST result (H-01.2 vocabulary).</summary>
    public static FailureSignatureMaterial FromTestResult(NormalizedTestResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));

        return new FailureSignatureMaterial
        {
            TestIdentity = result.Identity,
            RawMessage = CoalesceRaw(result.RawErrorMessage, result.ErrorMessage)
            // exception type / assertion type / location extraction lands
            // with H-02.2 normalization and H-03 stack parsing - the
            // material records only what BF-01 actually knows today.
        };
    }

    /// <summary>Material from a normalized DOMAIN evaluation result.</summary>
    public static FailureSignatureMaterial FromDomainEvaluation(NormalizedEvaluationResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));

        return new FailureSignatureMaterial
        {
            // SourceTestId names the test; assembly/class are unknown here
            // and stay EMPTY - never fabricated (H-01.4).
            TestIdentity = new FailureIdentity { TestName = result.SourceTestId ?? string.Empty },
            SubControlId = NullIfEmpty(result.SubControlId),
            DomainStatus = result.Status,
            RawMessage = NullIfEmpty(result.Reason)
        };
    }

    private static string? CoalesceRaw(string? raw, string? processed) =>
        string.IsNullOrWhiteSpace(raw) ? NullIfEmpty(processed) : raw;

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}