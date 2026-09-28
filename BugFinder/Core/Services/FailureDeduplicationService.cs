using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-02.4: Failure Deduplication Service.
/// Stage 2.4.1 Exact-signature dedup: instances group by FailureId.
/// Stage 2.4.2 Distinct separation: different signatures NEVER merge
///          (grouping is by content-derived id, not by test name).
/// Stage 2.4.3 Same-test/different-failure: falls out of 2.4.2 and is
///          pinned by test (the KBF-01-012 collapse is now impossible).
/// Stage 2.4.4 Composite separation: an aggregate and its components
///          have different content -> different signatures -> different
///          groups (pinned by test; composite modeling deepens in H-02.5).
/// Stage 2.4.5 Cross-run recurrence: same signature across sessions
///          links by signature alone (H-02.3 made signatures
///          session-independent precisely for this).
///
/// Nothing is discarded: instances with empty materials (no knowledge,
/// no signature possible) are EXCLUDED and counted explicitly in the
/// report (H-01.4: no fabrication, no silent drop).
/// Determinism: groups ordered by FailureId (ordinal); instances within
/// a group ordered by OccurredAtUtc then InstanceId.
/// </summary>
public class FailureDeduplicationService
{
    public FailureDeduplicationReport Deduplicate(IEnumerable<FailureInstance>? instances)
    {
        if (instances is null) throw new ArgumentNullException(nameof(instances));

        var all = instances.ToList();
        var excludedEmpty = 0;

        var groups = new Dictionary<string, List<FailureInstance>>(StringComparer.Ordinal);

        foreach (var instance in all)
        {
            if (instance is null) throw new ArgumentException(
                "Null instance in the input sequence.", nameof(instances));

            // Instances without a possible signature are excluded explicitly
            if (!instance.Material.HasAnyKnowledge)
            {
                excludedEmpty++;
                continue;
            }

            var key = instance.FailureId.Value;
            if (!groups.TryGetValue(key, out var bucket))
                groups[key] = bucket = new List<FailureInstance>();
            bucket.Add(instance);
        }

        var canonical = groups
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => BuildCanonical(g.Value))
            .ToList();

        return new FailureDeduplicationReport
        {
            CanonicalFailures = canonical,
            InputInstanceCount = all.Count,
            CanonicalCount = canonical.Count,
            CollapsedInstanceCount = all.Count - excludedEmpty - canonical.Count,
            RecurringCount = canonical.Count(c => c.IsRecurring),
            CrossSessionRecurringCount = canonical.Count(c => c.IsCrossSessionRecurring),
            ExcludedEmptyMaterialCount = excludedEmpty
        };
    }

    private static CanonicalFailure BuildCanonical(List<FailureInstance> bucket)
    {
        var ordered = bucket
            .OrderBy(i => i.OccurredAtUtc)
            .ThenBy(i => i.InstanceId.Value, StringComparer.Ordinal)
            .ToList();

        var sessions = ordered.Select(i => i.Session.Value).Distinct(StringComparer.Ordinal).ToList();
        var definitions = ordered.Select(i => i.TestDefinitionId)
            .Where(d => d.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToList();

        return new CanonicalFailure
        {
            FailureId = ordered[0].FailureId,
            Signature = ordered[0].Signature,
            Instances = ordered,
            DistinctSessionCount = sessions.Count,
            FirstSeenUtc = ordered[0].OccurredAtUtc,
            LastSeenUtc = ordered[^1].OccurredAtUtc,
            TestDefinitionIds = definitions
        };
    }
}