using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-02.5: Composite Failure Builder.
/// Builds the aggregate/component LINK record (2.5.3) between an
/// aggregate occurrence and its component occurrences - without moving
/// anything into or out of canonical groups (2.4 owns grouping; H-02.5
/// only adds the relationship evidence).
///
/// VALIDATION:
///   - Aggregate and components must have DIFFERENT signatures (the
///     aggregate's wrapper content is its own failure; a component with
///     the aggregate's signature would be a duplicate, not a part).
///   - Component ids are de-duplicated and ordered (deterministic).
///   - At least one side (aggregate or components) must exist.
///
/// Stage 2.5.4 (loss prevention): components remain independent
/// canonical-group members (H-02.4) - the link never removes them.
/// </summary>
public static class CompositeFailureBuilder
{
    public static CompositeFailureBuild Build(
        FailureInstance? aggregate,
        IReadOnlyList<FailureInstance>? components,
        string evidenceNote)
    {
        if (string.IsNullOrWhiteSpace(evidenceNote))
            throw new ArgumentException(
                "An evidence note is mandatory for every composite link " +
                "(H-02.5.3: links are evidence, not assumptions).",
                nameof(evidenceNote));

        var componentList = (components ?? Array.Empty<FailureInstance>()).ToList();
        if (componentList.Any(c => c is null))
            throw new ArgumentException("Null component instance.", nameof(components));

        if (aggregate is null && componentList.Count == 0)
            throw new ArgumentException(
                "Composite link requires an aggregate, components, or both.");

        // Aggregate must not swallow a component with identical content
        if (aggregate is not null && componentList.Any(c => c.Signature.Equals(aggregate.Signature)))
            throw new ArgumentException(
                "A component shares the aggregate's signature - that is a duplicate " +
                "occurrence, not a composite part (H-02.4 owns duplicates).",
                nameof(components));

        // Deterministic component ids
        var componentFailureIds = componentList
            .Select(c => c.FailureId)
            .Distinct()
            .OrderBy(f => f.Value, StringComparer.Ordinal)
            .ToList();

        var componentInstanceIds = componentList
            .Select(c => c.InstanceId)
            .Distinct()
            .OrderBy(i => i.Value, StringComparer.Ordinal)
            .ToList();

        var linkKind = (aggregate is null, componentList.Count == 0) switch
        {
            (false, false) => CompositeLinkKind.AggregateWithComponents,
            (false, true) => CompositeLinkKind.AggregateOnly,
            (true, false) => CompositeLinkKind.ComponentsOnly,
            _ => throw new InvalidOperationException("unreachable")
        };

        var link = new CompositeFailureRecord
        {
            AggregateInstanceId = aggregate?.InstanceId
                ?? FailureInstanceId.Create(
                    FailureId.Create($"F-{new string('0', 64)}"),
                    ExecutionSessionId.Create($"ES-{new string('0', 32)}")),
            AggregateFailureId = aggregate?.FailureId
                ?? FailureId.Create($"F-{new string('0', 64)}"),
            ComponentFailureIds = componentFailureIds,
            ComponentInstanceIds = componentInstanceIds,
            LinkKind = linkKind,
            EvidenceNote = evidenceNote.Trim()
        };

        return new CompositeFailureBuild
        {
            Aggregate = aggregate,
            Components = componentList
                .OrderBy(c => c.InstanceId.Value, StringComparer.Ordinal)
                .ToList(),
            Link = link
        };
    }
}