using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.7: Coverage Provenance Service.
/// Assigns first-class provenance to a parsed coverage artifact
/// (audit KBF-06-009 fix — see Models header for the stage map).
///
/// IDENTITY RULE: EvidenceId and ArtifactSha256 are derived ONLY from
/// the artifact bytes (SHA-256) — deterministic, replayable, and valid
/// against the H-01.2 canonical EvidenceId contract. No Guid, no clock
/// (X-003). Hashing works even for a CORRUPT artifact — identity of the
/// corrupt artifact is preserved as evidence (H-06.4.4 continuity).
///
/// EXPLICIT FAILURE STATES: artifact missing / unreadable => Status
/// carries it, EvidenceId and hash stay EMPTY, a diagnostic preserves
/// the reason — nothing is fabricated (H-01.4 / anti-KBF-11-004).
/// </summary>
public class CoverageProvenanceService
{
    public CoverageProvenanceRecord Build(CoverageProvenanceInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (input.Document is null) throw new ArgumentNullException(nameof(input.Document));

        var diagnostics = new List<string>();
        var document = input.Document;

        // ---------- Stage 4.7.3 — artifact content identity ----------
        var artifactPath = Path.GetFullPath(document.SourceArtifactPath);
        string sha256Hex;
        long? sizeBytes;

        if (!File.Exists(artifactPath))
        {
            diagnostics.Add(
                $"coverage artifact not found on disk: '{artifactPath}' — " +
                "no EvidenceId, no hash, nothing fabricated (H-01.4)");
            return Finalize(input, CoverageProvenanceStatus.ArtifactMissing,
                artifactPath, evidenceId: null, sha256Hex: string.Empty,
                sizeBytes: null, diagnostics);
        }

        try
        {
            var bytes = File.ReadAllBytes(artifactPath);
            sha256Hex = Convert.ToHexString(SHA256.HashData(bytes));   // 64 hex, repo precedent
            sizeBytes = bytes.LongLength;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            diagnostics.Add(
                $"coverage artifact unreadable: {ex.Message} — " +
                "no EvidenceId, no hash, corruption evidence preserved (H-06.4.4)");
            return Finalize(input, CoverageProvenanceStatus.ArtifactUnreadable,
                artifactPath, evidenceId: null, sha256Hex: string.Empty,
                sizeBytes: null, diagnostics);
        }

        // ---------- Stage 4.7.1 — content-derived canonical EvidenceId ----------
        var evidenceId = EvidenceId.Create(
            $"{EvidenceId.Prefix}-{sha256Hex[..EvidenceId.HexLength]}");

        // Stage 4.7.2 — collector version honesty (once per record)
        diagnostics.Add(
            "collector version Unknown: the cobertura artifact carries no tool " +
            "version and H-04.1 evidence does not capture one — not guessed");

        if (!input.HasMappingCompleteness)
            diagnostics.Add(
                "per-test mapping completeness not provided — provenance is " +
                "incomplete (KBF-06-009)");

        return Finalize(input, CoverageProvenanceStatus.Recorded,
            artifactPath, evidenceId, sha256Hex, sizeBytes, diagnostics);
    }

    // ---------- internals ----------

    private static CoverageProvenanceRecord Finalize(
        CoverageProvenanceInput input,
        CoverageProvenanceStatus status,
        string artifactPath,
        EvidenceId? evidenceId,
        string sha256Hex,
        long? sizeBytes,
        List<string> diagnostics)
    {
        var document = input.Document;

        // Stage 4.7.5 — parent artifact references (distinct, ordinal)
        var parents = new List<string>();
        if (artifactPath.Length > 0) parents.Add(artifactPath);
        if (input.Collection?.ArtifactPath is { Length: > 0 } collectionArtifact)
            parents.Add(collectionArtifact);
        if (input.TestSet is { } trx && trx.SourceArtifactPath.Length > 0)
            parents.Add(trx.SourceArtifactPath);
        if (input.Mapping is { } mapping)
            parents.AddRange(mapping.Entries
                .Where(e => e.SourceArtifactPath.Length > 0)
                .Select(e => e.SourceArtifactPath));

        return new CoverageProvenanceRecord
        {
            SchemaVersion = CoreSchema.CurrentVersion,
            Status = status,
            SessionId = input.Session,                       // 4.7.4 — injected; null = Unknown
            EvidenceId = evidenceId,
            ArtifactPath = artifactPath,
            ArtifactSha256 = sha256Hex,
            ArtifactSizeBytes = sizeBytes,
            CollectorName = document.CollectorName,          // 4.7.2 — verbatim (H-04.2)
            CollectorVersion = null,                         // Unknown — documented, never guessed
            CollectorArguments = input.Collection?.Arguments ?? Array.Empty<string>(),
            HasCollectionEvidence = input.Collection is not null,
            HasTestSet = input.TestSet is not null,
            TestSetStatus = input.TestSet?.Status,
            TestSetArtifactPath = input.TestSet?.SourceArtifactPath ?? string.Empty,
            TestRecordCount = input.TestSet?.Records.Count ?? 0,
            UnknownDefinitionCount = input.TestSet?.UnknownDefinitionCount ?? 0,
            HasMappingCompleteness = input.Mapping is not null,
            MappedCount = input.Mapping?.MappedCount ?? 0,
            UnmappedDocumentCount = input.Mapping?.UnmappedDocumentCount ?? 0,
            MissingCoverageCount = input.Mapping?.MissingCoverageCount ?? 0,
            TotalDistinctElements = input.Mapping?.TotalDistinctElements ?? 0,
            ParentArtifactPaths = parents
                .Distinct(StringComparer.Ordinal)
                .OrderBy(p => p, StringComparer.Ordinal)
                .ToList(),
            Diagnostics = diagnostics
        };
    }
}

/// <summary>
/// Provenance input: the parsed artifact (mandatory) plus every upstream
/// component available — each optional component's absence is recorded
/// explicitly on the record (never silently defaulted).
/// </summary>
public sealed class CoverageProvenanceInput
{
    /// <summary>H-04.2 parsed artifact — SourceArtifactPath is the hashed file.</summary>
    public CoverageDocument Document { get; init; } = null!;

    /// <summary>H-04.1 collection evidence (optional — command audit copy + artifact ref).</summary>
    public CoverageCollectionEvidence? Collection { get; init; }

    /// <summary>H-04.3 TRX source — test-set identity (optional).</summary>
    public TrxIngestionReport? TestSet { get; init; }

    /// <summary>H-04.3 mapping report — completeness metrics (optional).</summary>
    public PerTestCoverageReport? Mapping { get; init; }

    /// <summary>H-01.2 session identity — caller-injected; null = Unknown (4.7.4).</summary>
    public ExecutionSessionId? Session { get; init; }

    public bool HasMappingCompleteness => Mapping is not null;
}