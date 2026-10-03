namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.8: Coverage Gate Models (audit KBF-06-010: BF-12 consumed these
/// spectra with weak coverage ingestion — algorithmic correctness could
/// operate on untrustworthy data).
///
/// THE GATE CONTRACT (4.8.6): BF-12 spectrum analysis is authorized ONLY
/// through a PASSed gate. PASS requires POSITIVE evidence of every chain
/// link — Unknown/Partial/Missing/Unavailable can NEVER become PASS.
/// Suspiciousness != Root Cause: the gate authorizes INPUT VALIDITY only;
/// it never emits causal claims (boundary preserved to BF-15).
///
/// VERDICT SEMANTICS (explicit, deterministic):
///   Blocked — required evidence NOT SUPPLIED (cannot evaluate).
///   Fail    — evidence SUPPLIED but INVALID (evaluated and rejected).
///   Pass    — every stage positively verified.
/// </summary>
public enum CoverageGateVerdict
{
    /// <summary>Every chain link positively verified — BF-12 authorized.</summary>
    Pass,

    /// <summary>Required evidence not supplied — cannot evaluate (BF-12 disabled).</summary>
    Blocked,

    /// <summary>Evidence supplied but invalid — evaluated and rejected (BF-12 disabled).</summary>
    Fail
}

/// <summary>Machine-readable blocking reasons, grouped by gate stage.</summary>
public enum CoverageGateBlockReason
{
    // ---- 4.8.1 Real artifact exists ----
    /// <summary>H-04.1 collection evidence not supplied — real collection unprovable (Blocked-type).</summary>
    CollectionEvidenceMissing,
    /// <summary>Collection ran but produced no artifact (Status != Collected).</summary>
    CollectionNotCollected,
    /// <summary>Parsed document reports the artifact file missing (Blocked-type: prerequisite absent).</summary>
    CoverageArtifactMissing,
    /// <summary>Artifact unreadable XML — evaluated and rejected.</summary>
    CoverageArtifactCorrupt,
    /// <summary>Artifact is not a cobertura coverage document.</summary>
    CoverageArtifactUnsupportedFormat,
    /// <summary>Artifact parsed but contains zero modules.</summary>
    CoverageArtifactNoModules,
    /// <summary>Collection artifact path != parsed artifact path — run-to-artifact binding broken.</summary>
    ArtifactPathUnbound,

    // ---- 4.8.2 Test-to-code mapping ----
    /// <summary>Mapping report not supplied (Blocked-type).</summary>
    TestToCodeMappingUnavailable,
    /// <summary>Zero mapped tests — no test-to-code linkage exists.</summary>
    TestToCodeMappingIncomplete,

    // ---- 4.8.3 Pass/Fail spectrum ----
    /// <summary>Spectrum not supplied (Blocked-type).</summary>
    PassFailSpectrumUnavailable,
    /// <summary>TRX source not ingested — outcomes unmeasured; zero failures would be fabricated.</summary>
    TestSourceNotIngested,
    /// <summary>Unclassified (Unknown) outcomes present — spectrum is partially classified (KBF-06-004).</summary>
    UnclassifiedTestOutcomes,
    /// <summary>Classified tests produced zero element counters — nothing for BF-12 to rank.</summary>
    ElementSpectrumEmpty,

    // ---- 4.8.4 Domain mapping ----
    /// <summary>Domain report supplied but its source is not ingested — must not silently become "no domain signal".</summary>
    DomainSourceNotIngested,

    // ---- 4.8.5 Provenance ----
    /// <summary>Provenance record not supplied (Blocked-type).</summary>
    ProvenanceUnavailable,
    /// <summary>Provenance could not record the artifact (missing/unreadable).</summary>
    ProvenanceNotRecorded,
    /// <summary>Provenance lacks test-set identity or mapping completeness.</summary>
    ProvenanceIncomplete
}

/// <summary>The five gate stages (H-04.8.1 .. 4.8.5).</summary>
public enum CoverageGateStage
{
    RealArtifactExists,
    TestToCodeMapping,
    PassFailSpectrum,
    DomainMapping,
    Provenance
}

/// <summary>One stage's evaluation outcome with an honest detail line.</summary>
public sealed class CoverageGateStageResult
{
    public CoverageGateStage Stage { get; init; }
    public bool Passed { get; init; }
    public string Detail { get; init; } = string.Empty;
}

/// <summary>All upstream H-04 artifacts the gate evaluates. Domain is an
/// OPTIONAL signal (absence is honest, not fabricated); the rest are required
/// chain links — their absence is a Blocked verdict, never an exception.</summary>
public sealed class CoverageGateInput
{
    /// <summary>H-04.1 — binds the artifact to a REAL collection run (4.8.1).</summary>
    public CoverageCollectionEvidence? Collection { get; init; }

    /// <summary>H-04.2 — the parsed artifact (4.8.1).</summary>
    public CoverageDocument? Document { get; init; }

    /// <summary>H-04.3 — test-to-code mapping (4.8.2).</summary>
    public PerTestCoverageReport? Mapping { get; init; }

    /// <summary>H-04.5 — pass/fail spectrum (4.8.3).</summary>
    public PassFailSpectrumReport? Spectrum { get; init; }

    /// <summary>H-04.6 — domain correlation (4.8.4, optional signal).</summary>
    public DomainCoverageReport? Domain { get; init; }

    /// <summary>H-04.7 — provenance record (4.8.5).</summary>
    public CoverageProvenanceRecord? Provenance { get; init; }
}

/// <summary>
/// The gate's terminal report. IsBf12Enabled is the SINGLE authorization
/// point for BF-12 spectrum analysis (4.8.6); EnsureBf12Authorized is the
/// enforcement API downstream consumers MUST call (H-12 wiring).
/// </summary>
public sealed class CoverageGateReport
{
    public CoverageGateVerdict Verdict { get; init; }

    /// <summary>Empty for Pass. Deterministic order (stage evaluation order).</summary>
    public IReadOnlyList<CoverageGateBlockReason> BlockReasons { get; init; } =
        Array.Empty<CoverageGateBlockReason>();

    /// <summary>All five stages, evaluated independently (evidence even on failure).</summary>
    public IReadOnlyList<CoverageGateStageResult> Stages { get; init; } =
        Array.Empty<CoverageGateStageResult>();

    /// <summary>Honest recorded states (Unknown provenance fields, unresolved domain
    /// correlations, v1-attribution caveats) — never silently dropped, never blockers
    /// beyond the documented policy.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    /// <summary>4.8.6 — the single BF-12 authorization point. True ONLY for Pass.</summary>
    public bool IsBf12Enabled => Verdict == CoverageGateVerdict.Pass;

    /// <summary>
    /// 4.8.6 enforcement API: downstream BF-12 consumers MUST pass through
    /// this — a non-PASS verdict can never authorize spectrum analysis.
    /// </summary>
    public CoverageGateReport EnsureBf12Authorized()
    {
        if (!IsBf12Enabled)
            throw new InvalidOperationException(
                "BF-12 spectrum analysis is NOT authorized by the coverage gate " +
                $"(H-04.8.6): verdict={Verdict}, reasons=[{string.Join(", ", BlockReasons)}] — " +
                "coverage input integrity is a prerequisite, not a convention");
        return this;
    }
}