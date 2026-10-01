using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.6: Domain Failure Coverage Correlation Service.
/// (audit KBF-06-006 P0 / KBF-06-007 / KBF-06-008 — see Models header.)
///
/// Stage 4.6.1  domain source identity = SourceTestId (the record's only
///              real pointer; absent -> Unresolved, NEVER guessed).
/// Stage 4.6.2  domain failure location: the record carries none —
///              location stays Unknown BY CONTRACT; correlation is
///              identity-based, not location-based (honest absence).
/// Stage 4.6.3  covered elements from the matched test's MAPPED spectrum
///              (H-04.3) — hits>0 only (executed elements).
/// Stage 4.6.4  partial matches: unambiguous dotted-suffix only
///              ("TestName" == tail of "NS.Cls.TestName") — a bounded,
///              diagnosable rule replacing raw Contains (KBF-06-007).
/// Stage 4.6.5  multiple suffix candidates -> Ambiguous (all candidates
///              preserved, none picked); no match/absent id -> Unresolved.
/// Stage 4.6.6  no semantic claims: the service observes correlation
///              truth only — no "Missing Test Scenario" style
///              interpretation (KBF-06-008).
///
/// JOIN INPUT: PerTestCoverageReport (H-04.3) — names from ALL entries;
/// hits only from Mapped entries (union-max across duplicate names).
/// Domain Status/RawStatus are PRESERVED verbatim (H-03.8.5) — no
/// conversion, no filtering by status (the caller decides semantics;
/// the full CheckStatus vocabulary is not re-interpreted here).
/// Deterministic: ordinal ordering; no clock, no Guid (X-003).
/// </summary>
public class DomainCoverageCorrelationService
{
    public DomainCoverageReport Build(
        DomainResultIngestionReport domainResults,
        PerTestCoverageReport spectra)
    {
        if (domainResults is null) throw new ArgumentNullException(nameof(domainResults));
        if (spectra is null) throw new ArgumentNullException(nameof(spectra));

        var diagnostics = new List<string>();

        // Honest gate: no domain results ingested -> nothing fabricated (H-01.4)
        if (domainResults.Status != DomainResultIngestionStatus.Ingested)
        {
            diagnostics.Add(
                $"domain results source not ingested: status={domainResults.Status} " +
                $"artifact='{domainResults.SourceArtifactPath}' ({domainResults.Reason}) — " +
                "no correlation performed, none fabricated");
            return new DomainCoverageReport
            {
                SourceStatus = domainResults.Status,
                SourceArtifactPath = domainResults.SourceArtifactPath,
                Diagnostics = diagnostics
            };
        }

        // Test-name map from spectra: names from ALL entries, hits from MAPPED only
        var testHits = new Dictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);
        var testsWithMappedSpectrum = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in spectra.Entries)
        {
            if (string.IsNullOrEmpty(entry.TestFullName))
            {
                diagnostics.Add(
                    "spectrum entry with empty TestFullName (unmapped document) — " +
                    "excluded from domain correlation join");
                continue;
            }

            if (!testHits.TryGetValue(entry.TestFullName, out var hits))
            {
                hits = new Dictionary<string, int>(StringComparer.Ordinal);
                testHits[entry.TestFullName] = hits;
            }

            if (entry.Status != PerTestMappingStatus.Mapped) continue;

            testsWithMappedSpectrum.Add(entry.TestFullName);
            foreach (var kv in entry.ElementHits)
            {
                if (!hits.TryGetValue(kv.Key, out var existing) || kv.Value > existing)
                    hits[kv.Key] = kv.Value;
            }
        }

        var correlations = new List<DomainCoverageCorrelation>();
        var correlated = 0;
        var ambiguous = 0;
        var unresolved = 0;

        foreach (var record in domainResults.Records)
        {
            var sourceTestId = record.SourceTestId?.Trim() ?? string.Empty;

            // Stage 4.6.1 — identity never guessed
            if (sourceTestId.Length == 0)
            {
                unresolved++;
                diagnostics.Add(
                    $"domain record '{record.SubControlId}': SourceTestId absent — " +
                    "Unresolved (4.6.1: identity is never guessed)");
                correlations.Add(new DomainCoverageCorrelation
                {
                    SubControlId = record.SubControlId,
                    Status = record.Status,
                    RawStatus = record.RawStatus,
                    Reason = record.Reason,
                    SourceTestId = record.SourceTestId,
                    State = DomainCorrelationState.Unresolved,
                    MatchKind = DomainCorrelationMatchKind.None
                });
                continue;
            }

            // Exact match first (4.6.3)
            if (testHits.TryGetValue(sourceTestId, out var exactHits))
            {
                correlated++;
                correlations.Add(BuildCorrelated(
                    record, DomainCorrelationMatchKind.Exact, sourceTestId,
                    exactHits, testsWithMappedSpectrum.Contains(sourceTestId), diagnostics));
                continue;
            }

            // Stage 4.6.4 — bounded partial match: unambiguous dotted suffix
            var suffix = "." + sourceTestId;
            var candidates = testHits.Keys
                .Where(k => k.EndsWith(suffix, StringComparison.Ordinal))
                .OrderBy(k => k, StringComparer.Ordinal)
                .ToList();

            if (candidates.Count == 1)
            {
                var name = candidates[0];
                correlated++;
                correlations.Add(BuildCorrelated(
                    record, DomainCorrelationMatchKind.DottedSuffix, name,
                    testHits[name], testsWithMappedSpectrum.Contains(name), diagnostics));
                continue;
            }

            // Stage 4.6.5 — multiple candidates: Ambiguous, none picked
            if (candidates.Count > 1)
            {
                ambiguous++;
                diagnostics.Add(
                    $"domain record '{record.SubControlId}': SourceTestId " +
                    $"'{sourceTestId}' dotted-suffix matches {candidates.Count} distinct " +
                    "test names — Ambiguous, not resolved by picking one " +
                    "(anti-KBF-13-008 / KBF-06-007: no heuristic fallback)");
                correlations.Add(new DomainCoverageCorrelation
                {
                    SubControlId = record.SubControlId,
                    Status = record.Status,
                    RawStatus = record.RawStatus,
                    Reason = record.Reason,
                    SourceTestId = record.SourceTestId,
                    State = DomainCorrelationState.Ambiguous,
                    MatchKind = DomainCorrelationMatchKind.DottedSuffix,
                    AmbiguousCandidates = candidates
                });
                continue;
            }

            unresolved++;
            diagnostics.Add(
                $"domain record '{record.SubControlId}': no test matches " +
                $"SourceTestId '{sourceTestId}' — Unresolved (4.6.5)");
            correlations.Add(new DomainCoverageCorrelation
            {
                SubControlId = record.SubControlId,
                Status = record.Status,
                RawStatus = record.RawStatus,
                Reason = record.Reason,
                SourceTestId = record.SourceTestId,
                State = DomainCorrelationState.Unresolved,
                MatchKind = DomainCorrelationMatchKind.None
            });
        }

        var ordered = correlations
            .OrderBy(c => c.SubControlId, StringComparer.Ordinal)
            .ThenBy(c => c.SourceTestId ?? string.Empty, StringComparer.Ordinal)
            .ToList();

        return new DomainCoverageReport
        {
            SourceStatus = DomainResultIngestionStatus.Ingested,
            SourceArtifactPath = domainResults.SourceArtifactPath,
            Correlations = ordered,
            CorrelatedCount = correlated,
            AmbiguousCount = ambiguous,
            UnresolvedCount = unresolved,
            Diagnostics = diagnostics
        };
    }

    // ---------- internals ----------

    private static DomainCoverageCorrelation BuildCorrelated(
        DomainEvaluationRecord record,
        DomainCorrelationMatchKind kind,
        string matchedTestFullName,
        IReadOnlyDictionary<string, int> hits,
        bool hasMappedSpectrum,
        List<string> diagnostics)
    {
        // Covered = EXECUTED elements (hits>0) — instrumented-not-hit excluded
        // (H-04.3 CoveredElementCount continuity; 4.4.3 keeps the zero-hit
        // members in the universe, this is the outcome view)
        var covered = hits
            .Where(kv => kv.Value > 0)
            .Select(kv => kv.Key)
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        if (!hasMappedSpectrum)
            diagnostics.Add(
                $"domain record '{record.SubControlId}': matched test " +
                $"'{matchedTestFullName}' has no mapped coverage spectrum — " +
                "correlation kept with zero elements (missing coverage ≠ zero " +
                "coverage, H-01.4)");

        return new DomainCoverageCorrelation
        {
            SubControlId = record.SubControlId,
            Status = record.Status,
            RawStatus = record.RawStatus,
            Reason = record.Reason,
            SourceTestId = record.SourceTestId,
            State = DomainCorrelationState.Correlated,
            MatchKind = kind,
            MatchedTestFullName = matchedTestFullName,
            CoveredElementKeys = covered,
            MatchedTestHasCoverageSpectrum = hasMappedSpectrum
        };
    }
}