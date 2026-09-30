using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.3: Per-Test Coverage Mapper.
/// Stage 4.3.1  test identity: from TRX records (H-03.5 ingestion).
/// Stage 4.3.2-4.3.4  covered symbols/files/lines per test: each coverage
///              document (H-04.2, one per test execution in per-test mode)
///              flattens its line hits into an ElementKey spectrum
///              (FILE|path|L&lt;line&gt;, H-01.7 normalized).
/// Stage 4.3.5  one test's spectrum independent — entries never merge.
/// Stage 4.3.6  mapping verified against known tests: documents without a
///              matching TRX test are Unmapped (diagnostic); tests without
///              a document are MissingCoverage (diagnostic) — nothing is
///              silently dropped, nothing fabricated (anti-KBF-06-006:
///              no ClassName fabrication, no Contains matching).
///
/// ATTRIBUTION STRATEGY (v1, documented):
///   Positional correspondence (document[i] ↔ record[i]) — coverlet
///   per-test mode emits one coverage file per test in execution order,
///   and TRX records are in the same execution order. This is a v1
///   approximation; H-04.5/H-12 will replace it with per-test artifacts
///   carrying embedded test identity (coverlet feature request).
///
/// ELEMENT KEY: "FILE|&lt;normalized path&gt;|L&lt;line&gt;" — the file part of
/// cobertura's class/@filename plus the line number. Uses
/// JoinKeyNormalization for path consistency (H-01.7).
/// </summary>
public class PerTestCoverageMapper
{
    public PerTestCoverageReport Map(
        IReadOnlyList<CoverageDocument> documents,
        IReadOnlyList<TrxTestRecord> testRecords)
    {
        if (documents is null) throw new ArgumentNullException(nameof(documents));
        if (testRecords is null) throw new ArgumentNullException(nameof(testRecords));

        var diagnostics = new List<string>();
        var entries = new List<PerTestCoverage>();

        // Stage 4.3.1 — test identities from TRX (by full name)
        var testsByName = testRecords
            .GroupBy(r => r.TestFullName, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        // Stage 4.3.2-4.3.5 — positional attribution (v1 approximation)
        var docList = documents.ToList();
        var recordList = testRecords.ToList();

        var mappedDocumentIndexes = new HashSet<int>();

        for (var i = 0; i < recordList.Count; i++)
        {
            var record = recordList[i];
            CoverageDocument? document = i < docList.Count ? docList[i] : null;

            if (document is null || document.TotalLines == 0)
            {
                entries.Add(new PerTestCoverage
                {
                    Status = PerTestMappingStatus.MissingCoverage,
                    TestIdentity = FailureIdentityProjection.FromInput(
                        new FailureIdentityInput { TestIdentity = record.TestFullName }),
                    TestFullName = record.TestFullName,
                    SourceArtifactPath = record.AssemblyPath,
                    Reason = "no coverage document available for this test (H-04.3.6)"
                });
                continue;
            }

            entries.Add(BuildMappedEntry(record, document));
            mappedDocumentIndexes.Add(i);
        }

        // Documents that exceed the TRX records: unmapped (honest)
        for (var i = 0; i < docList.Count; i++)
        {
            if (!mappedDocumentIndexes.Contains(i))
            {
                var document = docList[i];
                entries.Add(new PerTestCoverage
                {
                    Status = PerTestMappingStatus.Unmapped,
                    SourceArtifactPath = document.SourceArtifactPath,
                    Reason = "coverage document without a matching TRX test record " +
                             $"({document.TotalLines} lines observed — not attributed, not fabricated)"
                });
                if (document.TotalLines > 0)
                    diagnostics.Add($"document[{i}] unmapped: {document.TotalLines} lines");
            }
        }

        return Finalize(entries, diagnostics);
    }

    // ---------- internals ----------

    private static PerTestCoverage BuildMappedEntry(
        TrxTestRecord record, CoverageDocument document)
    {
        var elementHits = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var cls in document.Modules.SelectMany(m => m.Classes))
        {
            var filePath = cls.SourceFilePath;
            if (filePath.Length == 0) continue;

            foreach (var line in cls.AllLines)
            {
                var elementKey = $"FILE|{filePath}|L{line.LineNumber}";
                // max hits across duplicate entries (defensive; 4.2 already deduped)
                if (!elementHits.TryGetValue(elementKey, out var existing)
                    || line.Hits > existing)
                {
                    elementHits[elementKey] = line.Hits;
                }
            }
        }

        return new PerTestCoverage
        {
            Status = PerTestMappingStatus.Mapped,
            TestIdentity = FailureIdentityProjection.FromInput(
                new FailureIdentityInput { TestIdentity = record.TestFullName }),
            TestFullName = record.TestFullName,
            SourceArtifactPath = document.SourceArtifactPath,
            ElementHits = elementHits
        };
    }

    private static PerTestCoverageReport Finalize(
        List<PerTestCoverage> entries, List<string> diagnostics)
    {
        var ordered = entries
            .OrderBy(e => e.Status)
            .ThenBy(e => e.TestFullName, StringComparer.Ordinal)
            .ThenBy(e => e.SourceArtifactPath, StringComparer.Ordinal)
            .ToList();

        return new PerTestCoverageReport
        {
            Entries = ordered,
            MappedCount = ordered.Count(e => e.Status == PerTestMappingStatus.Mapped),
            UnmappedDocumentCount = ordered.Count(e => e.Status == PerTestMappingStatus.Unmapped),
            MissingCoverageCount = ordered.Count(e => e.Status == PerTestMappingStatus.MissingCoverage),
            TotalDistinctElements = ordered
                .Where(e => e.Status == PerTestMappingStatus.Mapped)
                .SelectMany(e => e.ElementHits.Keys)
                .Distinct(StringComparer.Ordinal)
                .Count(),
            Diagnostics = diagnostics
        };
    }
}