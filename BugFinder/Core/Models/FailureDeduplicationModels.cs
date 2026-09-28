using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-02.4: Failure Deduplication Models (audit KBF-02-008: no real
/// signature-based deduplication engine existed).
///
/// GROUPING CONTRACT:
///   - Group key = FailureId (F-&lt;hex&gt;, H-01.2 typed id) — content-derived.
///   - NOTHING is discarded: every instance is kept as evidence inside
///     its canonical group; deduplication COLLAPSES VIEW, not evidence.
///   - Different signatures NEVER merge (2.4.2); composite components
///     stay separate from the aggregate (2.4.4).
/// </summary>

/// <summary>One canonical failure with all of its occurrences.</summary>
public sealed class CanonicalFailure
{
    /// <summary>F-&lt;hex&gt; — the logical failure (content-derived).</summary>
    public FailureId FailureId { get; init; } = null!;

    /// <summary>The shared content-derived signature of every instance in the group.</summary>
    public FailureSignature Signature { get; init; } = null!;

    /// <summary>All occurrences, ordered by OccurredAtUtc (then InstanceId for determinism).</summary>
    public IReadOnlyList<FailureInstance> Instances { get; init; } = Array.Empty<FailureInstance>();

    public int OccurrenceCount => Instances.Count;

    /// <summary>Distinct sessions across the occurrences (recurrence breadth).</summary>
    public int DistinctSessionCount { get; init; }

    public DateTimeOffset? FirstSeenUtc { get; init; }
    public DateTimeOffset? LastSeenUtc { get; init; }

    /// <summary>Same signature seen more than once (2.4.1/2.4.5).</summary>
    public bool IsRecurring => OccurrenceCount > 1;

    /// <summary>Recurring ACROSS sessions — the strongest recurrence signal (2.4.5).</summary>
    public bool IsCrossSessionRecurring => DistinctSessionCount > 1;

    /// <summary>Distinct runner test definitions inside the group (usually one).</summary>
    public IReadOnlyList<string> TestDefinitionIds { get; init; } = Array.Empty<string>();
}

/// <summary>Deduplication report — deterministic ordering throughout.</summary>
public sealed class FailureDeduplicationReport
{
    /// <summary>Canonical groups, ordered by FailureId value (ordinal).</summary>
    public IReadOnlyList<CanonicalFailure> CanonicalFailures { get; init; } =
        Array.Empty<CanonicalFailure>();

    public int InputInstanceCount { get; init; }

    /// <summary>Distinct canonical failures after grouping.</summary>
    public int CanonicalCount { get; init; }

    /// <summary>Instances that collapsed into an existing canonical failure
    /// (input - canonical; every one of them is RETAINED as evidence).</summary>
    public int CollapsedInstanceCount { get; init; }

    /// <summary>Canonical failures with more than one occurrence (2.4.1).</summary>
    public int RecurringCount { get; init; }

    /// <summary>Canonical failures recurring across sessions (2.4.5).</summary>
    public int CrossSessionRecurringCount { get; init; }

    /// <summary>Instances whose material carried no knowledge are counted
    /// here (they cannot produce a signature - H-02.2 fail-fast) and are
    /// EXCLUDED from grouping, never silently dropped.</summary>
    public int ExcludedEmptyMaterialCount { get; init; }
}