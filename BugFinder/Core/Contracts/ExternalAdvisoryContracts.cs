using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.5.6: External Advisory Boundary.
/// The Core emits ONLY Observation / CandidateSuspicion /
/// EvidenceOnlyConclusion (frozen H-01.5.1-1.5.3). Interpretive layers
/// outside the Core (future Remediation Extension, LLM advisory, human
/// tooling) may translate Core conclusions into advisory objects - but
/// the resulting claims belong to the ADVISORY, never to the Core.
/// These types carry no execution capability by design: producing them
/// has no side effects and grants no permissions (H-10 boundary).
/// </summary>
public enum ExternalAdvisoryClaimType
{
    /// <summary>Restates a Core observation (fact-level, evidence-backed).</summary>
    Observation,

    /// <summary>Advisory suspicion derived from Core candidates (ranked, non-causal).</summary>
    CandidateSuspicion,

    /// <summary>Advisory root-cause interpretation - EXPLICITLY non-Core
    /// (the Core itself never emits this, H-01.5.4).</summary>
    RootCauseInterpretation,

    /// <summary>Advisory suggested action - EXPLICITLY non-Core and
    /// non-executable (H-01.5.5: removed from Core conclusions).</summary>
    SuggestedAction
}

/// <summary>A claim produced OUTSIDE the Core, referencing Core evidence.</summary>
public sealed class ExternalAdvisoryRequest
{
    public ExternalAdvisoryClaimType ClaimType { get; init; }
    public string ClaimText { get; init; } = string.Empty;

    /// <summary>Must reference a Core conclusion (InvestigationReport or EvidenceOnlyConclusion).</summary>
    public string SourceConclusionReference { get; init; } = string.Empty;

    /// <summary>Advisory-layer provenance (tool / model / human) - never the Core.</summary>
    public string AdvisorySource { get; init; } = string.Empty;
}

/// <summary>H-01.5.7 seed: verdict for advisory claims (gate in H-13.14.7).</summary>
public sealed class ExternalAdvisoryVerdict
{
    public ExternalAdvisoryRequest Request { get; init; } = new();
    public bool IsAdvisoryOnly { get; init; }

    /// <summary>The claim was made by a non-Core layer and references Core evidence.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>True when the claim type is one the Core itself may never emit.</summary>
    public bool IsNonCoreClaimType =>
        ClaimType is ExternalAdvisoryClaimType.RootCauseInterpretation
                 or ExternalAdvisoryClaimType.SuggestedAction;

    private ExternalAdvisoryClaimType ClaimType => Request.ClaimType;
}