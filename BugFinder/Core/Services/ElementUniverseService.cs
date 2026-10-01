using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.4: Element Universe Service.
/// Builds the analyzable-element universe from coverage METADATA (H-04.2
/// documents — every instrumented line, hits=0 included) plus the mapped
/// per-test spectra (H-04.3) — NOT from observed hits alone (audit
/// KBF-06-005 fix).
///
/// Stage 4.4.1  element = one instrumented source line, keyed
///              FILE|&lt;path&gt;|L&lt;line&gt; (the exact H-04.3 join key — one
///              join key across the whole coverage pipeline).
/// Stage 4.4.2  non-executable exclusion: only instrumented lines enter
///              as Covered/Uncovered. Cobertura emits instrumented lines
///              only, so collector truth defines executability; a line
///              absent from metadata is never synthesized here.
/// Stage 4.4.3  uncovered preservation: instrumented + no mapped hit
///              = Uncovered — an explicit universe member, never absent
///              (Zero != Missing, H-01.4.8).
/// Stage 4.4.4  unknown preservation: an element present in a MAPPED
///              spectrum but absent from coverage metadata = Unknown —
///              kept, never dropped (Unknown != Unavailable, H-01.4.6).
/// Stage 4.4.5  determinism: ordinal ordering by ElementKey; no clock,
///              no Guid (X-003 continuity); identical inputs produce an
///              identical universe.
///
/// ATTRIBUTION HONESTY (H-04.3 continuity): only MAPPED spectra attribute
/// execution. Unmapped-document hits are never used to mark Covered —
/// they carry no test attribution and would fabricate test coverage.
/// Non-Parsed documents are skipped WITH a diagnostic — never silently
/// dropped (anti-KBF-01-005 pattern).
/// </summary>
public class ElementUniverseService
{
    public ElementUniverseReport Build(
        IReadOnlyList<CoverageDocument> documents,
        PerTestCoverageReport spectra)
    {
        if (documents is null) throw new ArgumentNullException(nameof(documents));
        if (spectra is null) throw new ArgumentNullException(nameof(spectra));

        var diagnostics = new List<string>();

        if (documents.Count == 0)
            diagnostics.Add(
                "no coverage documents provided - element universe is empty " +
                "(no instrumentation metadata; empty is not zero-coverage)");

        // Stage 4.4.2 — instrumented metadata from Parsed documents
        var instrumented = new Dictionary<string, (string Path, int Line)>(StringComparer.Ordinal);
        var parsedArtifactPaths = new List<string>();

        for (var i = 0; i < documents.Count; i++)
        {
            var document = documents[i];
            if (document is null)
            {
                diagnostics.Add($"document[{i}] is null - skipped, not silently dropped");
                continue;
            }

            if (document.Status != CoverageParsingStatus.Parsed)
            {
                diagnostics.Add(
                    $"document[{i}] skipped: status={document.Status} " +
                    $"artifact='{document.SourceArtifactPath}' ({document.Reason}) - " +
                    "not silently dropped");
                continue;
            }

            parsedArtifactPaths.Add(document.SourceArtifactPath);

            var instrumentedCount = 0;
            foreach (var cls in document.Modules.SelectMany(m => m.Classes))
            {
                if (cls.SourceFilePath.Length == 0) continue;

                foreach (var line in cls.AllLines)
                {
                    instrumented[ElementKey(cls.SourceFilePath, line.LineNumber)] =
                        (cls.SourceFilePath, line.LineNumber);
                    instrumentedCount++;
                }
            }

            if (instrumentedCount == 0)
                diagnostics.Add(
                    $"document[{i}] parsed but contains zero instrumented lines: " +
                    document.SourceArtifactPath);
        }

        // H-04.3 continuity — attributed hits from MAPPED spectra only
        var attributedHits = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var entry in spectra.Entries)
        {
            if (entry.Status != PerTestMappingStatus.Mapped) continue;

            foreach (var kv in entry.ElementHits)
            {
                if (!attributedHits.TryGetValue(kv.Key, out var existing)
                    || kv.Value > existing)
                {
                    attributedHits[kv.Key] = kv.Value;
                }
            }
        }

        // Stage 4.4.1 + 4.4.3 — instrumented elements: Covered or Uncovered
        var elements = new List<UniverseElement>();
        foreach (var pair in instrumented)
        {
            var isHit = attributedHits.TryGetValue(pair.Key, out var hits) && hits > 0;
            elements.Add(new UniverseElement
            {
                ElementKey = pair.Key,
                SourceFilePath = pair.Value.Path,
                LineNumber = pair.Value.Line,
                State = isHit ? ElementUniverseState.Covered : ElementUniverseState.Uncovered,
                IsInstrumented = true,
                MaxObservedHits = isHit ? hits : 0
            });
        }

        // Stage 4.4.4 — Unknown: observed in a mapped spectrum, absent from metadata
        foreach (var pair in attributedHits.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (instrumented.ContainsKey(pair.Key)) continue;

            if (!TryParseElementKey(pair.Key, out var path, out var line))
            {
                diagnostics.Add(
                    "mapped spectrum key is not FILE|path|L<line> - preserved in " +
                    $"diagnostics, excluded from universe: '{pair.Key}'");
                continue;
            }

            elements.Add(new UniverseElement
            {
                ElementKey = pair.Key,
                SourceFilePath = path,
                LineNumber = line,
                State = ElementUniverseState.Unknown,
                IsInstrumented = false,
                MaxObservedHits = pair.Value
            });
        }

        // Stage 4.4.5 — deterministic output: ordinal by ElementKey
        var ordered = elements
            .OrderBy(e => e.ElementKey, StringComparer.Ordinal)
            .ToList();

        return new ElementUniverseReport
        {
            Elements = ordered,
            SourceArtifactPaths = parsedArtifactPaths
                .Distinct(StringComparer.Ordinal)
                .OrderBy(p => p, StringComparer.Ordinal)
                .ToList(),
            Diagnostics = diagnostics
        };
    }

    // ---------- internals ----------

    /// <summary>The exact H-04.3 join-key format (single source of truth).</summary>
    private static string ElementKey(string filePath, int lineNumber) =>
        $"FILE|{filePath}|L{lineNumber}";

    private static bool TryParseElementKey(string key, out string path, out int line)
    {
        path = string.Empty;
        line = 0;

        const string prefix = "FILE|";
        if (!key.StartsWith(prefix, StringComparison.Ordinal)) return false;

        var rest = key[prefix.Length..];
        var separator = rest.LastIndexOf("|L", StringComparison.Ordinal);
        if (separator < 0) return false;

        path = rest[..separator];
        return int.TryParse(rest[(separator + 2)..], out line);
    }
}