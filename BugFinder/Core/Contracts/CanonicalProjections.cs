using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.6: Canonical Domain Model Map + Boundary Projections
/// (audit KBF-00-003 / X-006: overlapping identity models drifted).
///
/// CANONICAL MODEL MAP - one canonical model per concept; every other
/// shape is an explicit boundary projection of the canonical one:
///
///   Concept: FAILURE IDENTITY
///     Canonical : FailureIdentity             (BF-01: Assembly/Class/Test)
///     Views     : FailureIdentityInput        (BF-14.3 chain DTO)
///                 FailureRecord               (BF-11 history DTO - H-06 owns)
///
///   Concept: SOURCE LOCATION
///     Canonical : SourceLocation              (BF-03: File/Line/Method)
///     Views     : FailureLocation             (BF-14.3 chain view + IsPrimary)
///                 LocationId                  (H-01.2 typed id)
///
///   Concept: SUSPICIOUS TARGET
///     Canonical : CorrelatedTarget            (BF-14.2: TargetKey-based)
///     Views     : EvidenceRankedCandidate     (BF-12.10)
///                 RankedFaultCandidate        (BF-12.9)
///                 SuspiciousLocation          (BF-12 SBFL)
///                 ExperimentalSuspiciousness  (BF-15.7)
///
/// EQUIVALENCE RULE (H-01.6.6): the same event mapped through any two
/// projections yields the same canonical identity strings
/// (FailureIdentity.ToFullString() / LocationId / TargetKey). Tests pin
/// this. Physical model collapse happens at the H-02 (identity) and
/// H-05 (regression) adoption points; until then projections keep the
/// semantics non-competing (H-01 exit gate).
///
/// PARSE POLICY (no fabrication): FromInput never invents unknown
/// segments - an assembly it cannot know stays EMPTY.
/// </summary>
public static class FailureIdentityProjection
{
    /// <summary>
    /// Parse TestIdentity into the canonical FailureIdentity. Accepted:
    ///   "Assembly:Class.Test"  (canonical ToFullString format - exact)
    ///   "NS.Class.Test"        (assembly unknown -> empty)
    ///   "Test"                 (only the test is known)
    /// The LAST dot separates class from test; text before ':' (if any)
    /// is the assembly.
    /// </summary>
    public static FailureIdentity FromInput(FailureIdentityInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        var testIdentity = input.TestIdentity?.Trim() ?? string.Empty;
        if (testIdentity.Length == 0)
            return new FailureIdentity();

        var assembly = string.Empty;
        var remainder = testIdentity;

        var separator = testIdentity.IndexOf(':');
        if (separator >= 0)
        {
            assembly = testIdentity[..separator].Trim();
            remainder = testIdentity[(separator + 1)..].Trim();
        }

        var lastDot = remainder.LastIndexOf('.');
        if (lastDot <= 0)
            return new FailureIdentity
            {
                AssemblyName = assembly,
                ClassName = string.Empty,
                TestName = remainder
            };

        return new FailureIdentity
        {
            AssemblyName = assembly,
            ClassName = remainder[..lastDot],
            TestName = remainder[(lastDot + 1)..]
        };
    }

    /// <summary>
    /// Project the canonical identity into the BF-14.3 chain DTO.
    /// TestIdentity uses the canonical ToFullString() format, so
    /// FromInput(ToInput(x)) reproduces x exactly.
    /// </summary>
    public static FailureIdentityInput ToInput(
        FailureIdentity identity,
        string? evaluationIdentity = null,
        string? failureCategory = null,
        string? failureSignature = null)
    {
        if (identity is null) throw new ArgumentNullException(nameof(identity));

        return new FailureIdentityInput
        {
            TestIdentity = identity.ToFullString(),
            EvaluationIdentity = evaluationIdentity,
            FailureCategory = failureCategory,
            FailureSignature = failureSignature
        };
    }
}

/// <summary>
/// H-01.6.2: Source Location projections.
/// Canonical: SourceLocation (BF-03). Chain view adds IsPrimary - chain
/// metadata only, never part of the identity.
/// </summary>
public static class SourceLocationProjection
{
    /// <summary>Chain view -> canonical (IsPrimary is chain metadata, dropped).</summary>
    public static SourceLocation ToCanonical(FailureLocation location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return new SourceLocation
        {
            FilePath = location.FilePath,
            LineNumber = location.LineNumber,
            MethodName = location.MethodName
        };
    }

    /// <summary>Canonical -> chain view (H-01.6.4: IsPrimary set only at the boundary).</summary>
    public static FailureLocation ToChainView(SourceLocation location, bool isPrimary = false)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return new FailureLocation
        {
            FilePath = location.FilePath ?? string.Empty,
            LineNumber = location.LineNumber,
            MethodName = location.MethodName,
            IsPrimary = isPrimary
        };
    }

    /// <summary>
    /// Typed location identity. Null when the location carries no file
    /// path (method-only knowledge) - identity is never fabricated.
    /// </summary>
    public static LocationId? ToLocationId(SourceLocation location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return ToLocationId(location.FilePath, location.LineNumber);
    }

    public static LocationId? ToLocationId(FailureLocation location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return ToLocationId(location.FilePath, location.LineNumber);
    }

    private static LocationId? ToLocationId(string? filePath, int? lineNumber) =>
        string.IsNullOrWhiteSpace(filePath) ? null : LocationId.Create(filePath, lineNumber);
}

/// <summary>
/// H-01.6.3: Suspicious Target projections.
/// Every suspicious-location view feeds the H-01.2 identity contracts:
/// the same ElementId/TargetKey string yields the same TargetKey, and
/// the same File+Line yields the same LocationId, across ALL views.
/// </summary>
public static class SuspiciousTargetProjection
{
    public static TargetKey TargetKeyOf(CorrelatedTarget target)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        return TargetKey.FromRaw(target.TargetKey);
    }

    public static TargetKey TargetKeyOf(EvidenceRankedCandidate candidate)
    {
        if (candidate is null) throw new ArgumentNullException(nameof(candidate));
        return TargetKey.FromRaw(candidate.ElementId);
    }

    public static TargetKey TargetKeyOf(RankedFaultCandidate candidate)
    {
        if (candidate is null) throw new ArgumentNullException(nameof(candidate));
        return TargetKey.FromRaw(candidate.ElementId);
    }

    public static TargetKey TargetKeyOf(SuspiciousLocation location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return TargetKey.FromRaw(location.ElementId);
    }

    public static TargetKey TargetKeyOf(ExperimentalSuspiciousness location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return TargetKey.FromRaw(location.ElementId);
    }

    public static LocationId? LocationIdOf(EvidenceRankedCandidate candidate)
    {
        if (candidate is null) throw new ArgumentNullException(nameof(candidate));
        return LocationIdOf(candidate.FilePath, candidate.LineNumber);
    }

    public static LocationId? LocationIdOf(RankedFaultCandidate candidate)
    {
        if (candidate is null) throw new ArgumentNullException(nameof(candidate));
        return LocationIdOf(candidate.FilePath, candidate.LineNumber);
    }

    public static LocationId? LocationIdOf(SuspiciousLocation location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return LocationIdOf(location.FilePath, location.LineNumber);
    }

    public static LocationId? LocationIdOf(ExperimentalSuspiciousness location)
    {
        if (location is null) throw new ArgumentNullException(nameof(location));
        return LocationIdOf(location.FilePath, location.LineNumber);
    }

    private static LocationId? LocationIdOf(string? filePath, int? lineNumber) =>
        string.IsNullOrWhiteSpace(filePath) ? null : LocationId.Create(filePath, lineNumber);
}

/// <summary>
/// H-01.6.1: history record -> canonical identity.
/// History knows the test name only (assembly/class stay EMPTY - never
/// fabricated). Full history linkage lands in H-06.
/// </summary>
public static class FailureRecordProjection
{
    public static FailureIdentity ToIdentity(FailureRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        return new FailureIdentity { TestName = record.TestName ?? string.Empty };
    }

    public static LocationId? ToLocationId(FailureRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        return string.IsNullOrWhiteSpace(record.FilePath)
            ? null
            : LocationId.Create(record.FilePath, record.LineNumber);
    }
}