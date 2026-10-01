using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.5: Pass/Fail Spectrum Service.
/// (audit KBF-06-004 P1: CoverageSpectrumBuilderService treats every
/// non-passed test as failed because totalFailed = Count(!IsPassed) —
/// skipped/unknown outcomes contaminate the spectrum).
///
/// THE FIX: every test outcome is mapped EXPLICITLY from the real TRX
/// raw outcome (H-03.5) into one canonical bucket. ONLY Passed/Failed/
/// Error enter the element spectrum counters; Skipped/Unavailable/
/// Unknown are excluded WITH diagnostics — never counted as failed.
///
/// Stage 4.5.1  passed tests → Passed bucket
/// Stage 4.5.2  failed tests → Failed bucket
/// Stage 4.5.3  error results → Error bucket (separate from Failed)
/// Stage 4.5.4  unavailable execution → Unavailable bucket
/// Stage 4.5.5  outcome provenance: raw outcome VERBATIM + TRX artifact
///              path + real assembly path, per classification.
///
/// OUTCOME MAPPING (documented, test-pinned; TRX/VS result vocabulary —
/// the four values "Passed"/"Failed"/"NotExecuted"/"Skipped" are pinned
/// by the existing H-03.8 FromTrx contract):
///   Passed                              → Passed
///   Failed                              → Failed
///   Error | Timeout | Aborted |
///   PassedButRunAborted                 → Error
///   NotExecuted | Skipped               → Skipped
///   NotRunnable | Disconnected          → Unavailable
///   Warning | Inconclusive |
///   InProgress | Pending                → Unknown
///   anything else (incl. absent attr)   → Unknown (raw preserved, never guessed)
///
/// SPECTRUM JOIN (H-04.3 continuity): outcomes join per-test spectra by
/// TestFullName (ordinal). Duplicate TRX names with CONFLICTING outcomes
/// are ambiguous under positional attribution (H-04.3 v1) — excluded
/// from the element spectrum WITH a diagnostic, never resolved by
/// picking one (anti-KBF-13-008 pattern).
/// </summary>
public class PassFailSpectrumService
{
    public PassFailSpectrumReport Build(
        TrxIngestionReport trx,
        PerTestCoverageReport spectra)
    {
        if (trx is null) throw new ArgumentNullException(nameof(trx));
        if (spectra is null) throw new ArgumentNullException(nameof(spectra));

        var diagnostics = new List<string>();

        // Honest gate: no TRX ingested → no outcomes fabricated (H-01.4)
        if (trx.Status != TrxIngestionStatus.Ingested)
        {
            diagnostics.Add(
                $"TRX source not ingested: status={trx.Status} " +
                $"artifact='{trx.SourceArtifactPath}' ({trx.Reason}) — " +
                "no outcome classification performed, none fabricated");
            return new PassFailSpectrumReport
            {
                SourceStatus = trx.Status,
                SourceArtifactPath = trx.SourceArtifactPath,
                Diagnostics = diagnostics
            };
        }

        // Stage 4.5.1-4.5.5 — classify every TRX record (provenance per record)
        var classifications = trx.Records
            .Select(r => new TestOutcomeClassification
            {
                TestFullName = r.TestFullName,
                RawOutcome = r.Outcome,
                Outcome = ClassifyOutcome(r.Outcome),
                TrxArtifactPath = trx.SourceArtifactPath,
                AssemblyPath = r.AssemblyPath,
                IsUnknownDefinition = r.IsUnknownDefinition
            })
            .OrderBy(c => c.TestFullName, StringComparer.Ordinal)
            .ThenBy(c => c.RawOutcome, StringComparer.Ordinal)
            .ToList();

        // Spectrum join map — conflicting duplicate names are ambiguous
        var joinable = new Dictionary<string, SpectrumTestOutcome>(StringComparer.Ordinal);
        foreach (var group in classifications.GroupBy(c => c.TestFullName, StringComparer.Ordinal))
        {
            if (group.Key.Length == 0)
            {
                diagnostics.Add(
                    "TRX record with empty TestFullName — excluded from spectrum join");
                continue;
            }

            var distinct = group.Select(c => c.Outcome).Distinct().ToList();
            if (distinct.Count > 1)
            {
                diagnostics.Add(
                    $"ambiguous test name '{group.Key}': {distinct.Count} conflicting " +
                    $"outcomes ({string.Join("/", distinct.Select(o => o.ToString()))}) — " +
                    "excluded from element spectrum, not resolved by picking one");
                continue;
            }

            joinable[group.Key] = distinct[0];
        }

        // Element spectrum — ONLY Passed/Failed/Error enter the counters
        // (KBF-06-004 fix: skipped/unknown/unavailable never count as failed)
        var elementMap = new Dictionary<string, (int Passed, int Failed, int Error)>(StringComparer.Ordinal);
        foreach (var entry in spectra.Entries)
        {
            if (entry.Status != PerTestMappingStatus.Mapped) continue;   // H-04.3 owns unmapped/missing

            if (!joinable.TryGetValue(entry.TestFullName, out var outcome))
            {
                diagnostics.Add(
                    $"mapped spectrum without a classifiable TRX outcome: " +
                    $"'{entry.TestFullName}' — excluded from element spectrum");
                continue;
            }

            if (outcome is not (SpectrumTestOutcome.Passed
                or SpectrumTestOutcome.Failed
                or SpectrumTestOutcome.Error))
            {
                diagnostics.Add(
                    $"test '{entry.TestFullName}' excluded from element spectrum: " +
                    $"outcome={outcome} (KBF-06-004: non-passed is not failed)");
                continue;
            }

            foreach (var kv in entry.ElementHits)
            {
                if (kv.Value <= 0) continue;   // instrumented-not-hit: no execution attributed

                if (!elementMap.TryGetValue(kv.Key, out var counters))
                    counters = (0, 0, 0);

                elementMap[kv.Key] = outcome switch
                {
                    SpectrumTestOutcome.Passed => (counters.Passed + 1, counters.Failed, counters.Error),
                    SpectrumTestOutcome.Failed => (counters.Passed, counters.Failed + 1, counters.Error),
                    _ => (counters.Passed, counters.Failed, counters.Error + 1)
                };
            }
        }

        var elements = elementMap
            .OrderBy(e => e.Key, StringComparer.Ordinal)
            .Select(e => new ElementOutcomeSpectrum
            {
                ElementKey = e.Key,
                PassedHitCount = e.Value.Passed,
                FailedHitCount = e.Value.Failed,
                ErrorHitCount = e.Value.Error
            })
            .ToList();

        return new PassFailSpectrumReport
        {
            SourceStatus = trx.Status,
            SourceArtifactPath = trx.SourceArtifactPath,
            TestOutcomes = classifications,
            Elements = elements,
            Diagnostics = diagnostics
        };
    }

    /// <summary>
    /// Documented, test-pinned TRX raw outcome → canonical bucket.
    /// Unknown for ANY unrecognized value — raw is preserved on the
    /// classification (never guessed, never fabricated).
    /// </summary>
    public static SpectrumTestOutcome ClassifyOutcome(string rawOutcome)
    {
        return rawOutcome switch
        {
            "Passed" => SpectrumTestOutcome.Passed,                    // 4.5.1
            "Failed" => SpectrumTestOutcome.Failed,                    // 4.5.2
            "Error" or "Timeout" or "Aborted" or "PassedButRunAborted"
                => SpectrumTestOutcome.Error,                          // 4.5.3
            "NotExecuted" or "Skipped" => SpectrumTestOutcome.Skipped,
            "NotRunnable" or "Disconnected" => SpectrumTestOutcome.Unavailable,   // 4.5.4
            _ => SpectrumTestOutcome.Unknown                           // incl. absent attribute
        };
    }
}