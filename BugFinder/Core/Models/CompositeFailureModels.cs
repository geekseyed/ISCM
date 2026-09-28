using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-02.5: Composite Failure Model (audit KBF-02-007 P0: the composite
/// test asserted a result count of ONE - codifying component loss).
///
/// MODEL: a composite occurrence is an AGGREGATE failure instance whose
/// signature (the wrapper content) is DIFFERENT from its components'
/// signatures. Per H-02.4, aggregate and components live in SEPARATE
/// canonical groups - nothing is swallowed. This record adds the LINK:
/// which component failures belong to which aggregate occurrence.
///
/// Stage map:
///   2.5.1  Component representation - each component is an independent
///          FailureInstance with its own signature (H-02.3).
///   2.5.2  Aggregate representation - the wrapper occurrence (its
///          message/type describes the composite event itself).
///   2.5.3  Linking - by typed ids: aggregate FailureId + component
///          FailureIds (+ component InstanceIds when known).
///   2.5.4  Component loss prevention - enforced by H-02.4 (separate
///          canonical groups) and pinned by tests here.
///   2.5.5  Composite test semantics - a two-failure composite test MUST
///          produce two component instances; the old one-result shape is
///          structurally impossible now.
///
/// LINK DIRECTION: aggregate -> components. A component may appear in
/// several composites (fan-out) - the link is a fact about THIS composite.
/// </summary>
public sealed class CompositeFailureRecord
{
    /// <summary>The aggregate (wrapper) occurrence id.</summary>
    public FailureInstanceId AggregateInstanceId { get; init; } = null!;

    /// <summary>The aggregate's logical failure id (its own signature group).</summary>
    public FailureId AggregateFailureId { get; init; } = null!;

    /// <summary>Component failure ids (logical) linked to this aggregate.</summary>
    public IReadOnlyList<FailureId> ComponentFailureIds { get; init; } = Array.Empty<FailureId>();

    /// <summary>Component occurrence ids, when the concrete instances are known.</summary>
    public IReadOnlyList<FailureInstanceId> ComponentInstanceIds { get; init; } =
        Array.Empty<FailureInstanceId>();

    /// <summary>How the link was established (builder mode).</summary>
    public string LinkKind { get; init; } = string.Empty;

    /// <summary>Mandatory: why this link exists (evidence reference).</summary>
    public string EvidenceNote { get; init; } = string.Empty;
}

/// <summary>Builder result: aggregate + components + the link record.</summary>
public sealed class CompositeFailureBuild
{
    public FailureInstance? Aggregate { get; init; }
    public IReadOnlyList<FailureInstance> Components { get; init; } = Array.Empty<FailureInstance>();
    public CompositeFailureRecord? Link { get; init; }
}

/// <summary>H-02.5 builder modes (recorded verbatim into Link.LinkKind).</summary>
public static class CompositeLinkKind
{
    public const string AggregateWithComponents = "aggregate-with-components";
    public const string AggregateOnly = "aggregate-only";
    public const string ComponentsOnly = "components-only";
}