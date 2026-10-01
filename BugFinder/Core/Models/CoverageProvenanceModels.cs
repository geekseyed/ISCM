using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.7: Coverage Provenance Models
/// (audit KBF-06-009: coverage summary did not retain coverage artifact
/// identity, collector version, test-set identity and mapping
/// completeness as first-class provenance — coverage-derived suspicion
/// could not be independently audited.)
///
/// Stage 4.7.1  EvidenceId: CONTENT-DERIVED (EV-&lt;first 32 hex of the
///              artifact SHA-256&gt;) — deterministic, replayable, valid
///              against the H-01.2 canonical EvidenceId contract. Core
///              never generates random ids (X-003 / CanonicalIdentifiers).
/// Stage 4.7.2  collector name carried VERBATIM from the parsed document
///              (H-04.2); collector VERSION: coverlet's cobertura output
///              carries no tool version and H-04.1 evidence does not
///              capture one — version stays Unknown (null), never
///              fabricated.
/// Stage 4.7.3  artifact SHA-256 (full 64 hex) — the immutable content
///              identity (H-08.9 seed).
/// Stage 4.7.4  ExecutionSessionId — caller-INJECTED (H-01.2: no
///              generation inside Core); absent = Unknown, explicit.
/// Stage 4.7.5  parent artifact references: coverage artifact + TRX
///              artifact + per-test spectrum artifacts — distinct,
///              ordinal-ordered (provenance DAG seed, X-007).
///
/// EXPLICIT STATES: artifact missing/unreadable = Recorded never
/// happens — no EvidenceId, no hash, NOTHING fabricated (Zero !=
/// Missing, H-01.4; anti-KBF-11-004).
/// </summary>
public enum CoverageProvenanceStatus
{
    /// <summary>Artifact read, hashed, identity assigned.</summary>
    Recorded,

    /// <summary>Artifact path known but the file does not exist on disk.</summary>
    ArtifactMissing,

    /// <summary>Artifact reached but unreadable (IO failure — reason preserved).</summary>
    ArtifactUnreadable
}

/// <summary>
/// One coverage artifact's first-class provenance record
/// (audit KBF-06-009 fix). Flat, serializable, versioned.
/// </summary>
public sealed class CoverageProvenanceRecord
{
    /// <summary>H-01.3 single source of truth (CoreSchema.CurrentVersion).</summary>
    public int SchemaVersion { get; init; }

    public CoverageProvenanceStatus Status { get; init; }

    // Stage 4.7.4 — session identity (injected; null = Unknown)
    public ExecutionSessionId? SessionId { get; init; }

    // Stage 4.7.1 — content-derived canonical evidence identity
    /// <summary>Null when the artifact could not be read — never fabricated.</summary>
    public EvidenceId? EvidenceId { get; init; }

    // Artifact identity (4.7.3)
    public string ArtifactPath { get; init; } = string.Empty;
    /// <summary>Full SHA-256 hex (64, uppercase). Empty when Status != Recorded.</summary>
    public string ArtifactSha256 { get; init; } = string.Empty;
    public long? ArtifactSizeBytes { get; init; }

    // Stage 4.7.2 — collector identity
    /// <summary>Verbatim from the parsed document (H-04.2).</summary>
    public string CollectorName { get; init; } = string.Empty;
    /// <summary>Unknown (null) — coverlet output carries no tool version; never guessed.</summary>
    public string? CollectorVersion { get; init; }
    /// <summary>H-04.1.5 audit copy of the collection command, verbatim (when collection evidence provided).</summary>
    public IReadOnlyList<string> CollectorArguments { get; init; } = Array.Empty<string>();
    public bool HasCollectionEvidence { get; init; }

    // Test-set identity (KBF-06-009)
    public bool HasTestSet { get; init; }
    public TrxIngestionStatus? TestSetStatus { get; init; }
    public string TestSetArtifactPath { get; init; } = string.Empty;
    public int TestRecordCount { get; init; }
    public int UnknownDefinitionCount { get; init; }

    // Mapping completeness (KBF-06-009)
    public bool HasMappingCompleteness { get; init; }
    public int MappedCount { get; init; }
    public int UnmappedDocumentCount { get; init; }
    public int MissingCoverageCount { get; init; }
    public int TotalDistinctElements { get; init; }

    // Stage 4.7.5 — parent artifact references (distinct, ordinal)
    public IReadOnlyList<string> ParentArtifactPaths { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}