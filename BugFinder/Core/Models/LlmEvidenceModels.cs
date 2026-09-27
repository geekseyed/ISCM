using System;
using System.Collections.Generic;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// BF-15.6: LLM-Assisted Evidence Analysis Models (research only).
/// An LLM may READ serialized evidence and PROPOSE claims; every claim
/// is then validated against actual evidence via the BF-14.9 claim
/// validator (single truth). LLM output never enters the investigation
/// body un-validated, and fix/repair claims are refused structurally.
/// </summary>

public enum LlmClaimKind { Suspicion, RootCauseHypothesis, FixSuggestion, Other }

/// <summary>A parsed claim from the analyzer output (Stage 4).</summary>
public class LlmClaim
{
    public LlmClaimKind Kind { get; set; }
    public string ClaimText { get; set; } = string.Empty;
    public string? TargetKey { get; set; }
    public double ClaimedConfidence { get; set; }
    public int ClaimedDistinctSources { get; set; }
    public int ClaimedHighConflicts { get; set; }
    public string? RawLine { get; set; }
}

public enum LlmClaimDecision { Accepted, Rejected, Refused }

/// <summary>Stage 5/6: validation outcome of one LLM claim.</summary>
public class LlmClaimVerdict
{
    public LlmClaim Claim { get; set; } = new();
    public LlmClaimDecision Decision { get; set; }
    public string Reason { get; set; } = string.Empty;

    /// <summary>BF-14.9 verdict when the claim passed the structural refusal.</summary>
    public ClaimVerdict? CoreVerdict { get; set; }

    public bool UncertaintyPreserved => Decision != LlmClaimDecision.Accepted;
}

/// <summary>Stage 2: bounded context handed to the analyzer.</summary>
public class EvidenceAnalysisContext
{
    public string ScenarioName { get; set; } = string.Empty;
    public string EvidenceJson { get; set; } = string.Empty;
    public int EvidenceInputCount { get; set; }
    public int CorroboratedCount { get; set; }
    public int ConflictCount { get; set; }
    public int UnresolvedConflictCount { get; set; }
    public InvestigationOutcome Outcome { get; set; }
    public DateTime ConstructedAtUtc { get; set; } = DateTime.UtcNow;
}

public class LlmEvidenceAnalysisReport
{
    public string ScenarioName { get; set; } = string.Empty;
    public string AnalyzerName { get; set; } = string.Empty;

    public EvidenceAnalysisContext? Context { get; set; }
    public List<LlmClaim> Claims { get; set; } = new();
    public List<LlmClaimVerdict> Verdicts { get; set; } = new();

    public int TotalClaims { get; set; }
    public int AcceptedClaims { get; set; }
    public int RejectedClaims { get; set; }
    public int RefusedClaims { get; set; }

    public bool IsExperimental { get; set; } = true;
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

    public const string DisclaimerText =
        "EXPERIMENTAL (BF-15.6): LLM-assisted analysis - not production guidance. " +
        "LLM output is external evidence PROPOSALS only; every claim is validated " +
        "against actual evidence (BF-14.9), fix/repair claims are refused " +
        "structurally, and the Core executes no repair. LLM text never enters " +
        "the investigation body un-validated.";

    /// <summary>Serializable view (const strings are invisible to System.Text.Json - 15.7 lesson).</summary>
    public string Disclaimer => DisclaimerText;
}