using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-15.6: LLM-Assisted Evidence Analysis Service
/// Stage 1: serialize the official BF-14.8 investigation report to JSON
///          (single evidence source - what the LLM may see).
/// Stage 2: build a bounded context (scenario, sizes, conflicts, outcome).
/// Stage 3: ILlmEvidenceAnalyzer contract - real LLMs live OUTSIDE the
///          Core (network calls / prompts are forbidden here, BF-14.9);
///          ScriptedLlmAnalyzer ships in-Core for research, deterministically.
/// Stage 4: parse analyzer output into claims (deterministic format).
/// Stage 5: Evidence-to-Claim Validation - every claim runs through the
///          BF-14.9 claim validator (single truth); results recorded,
///          uncertainty preserved on rejection.
/// Stage 6: Strict No-Repair - fix/repair-flavored claims are refused
///          structurally BEFORE validation, regardless of evidence.
/// </summary>
public class LlmEvidenceAnalysisService
{
    private static readonly string[] RepairTokens =
        { "fix", "repair", "patch", "autofix", "auto-fix" };

    private readonly NoRepairEnforcementService _enforcement = new();

    public const string ResearchBoundaryNote =
        "BF-15.6 research output: LLM claims are proposals, not findings. " +
        "Read-only Core - no LLM calls, no prompts, no repair execution.";

    // Stage 1 — single evidence source: the official Core report
    public string SerializeEvidence(InvestigationReport? report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        return JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    }

    // Stage 2 — bounded context
    public EvidenceAnalysisContext BuildContext(string scenarioName, InvestigationReport? report)
    {
        if (scenarioName is null) throw new ArgumentNullException(nameof(scenarioName));

        return new EvidenceAnalysisContext
        {
            ScenarioName = scenarioName,
            EvidenceJson = report is null ? string.Empty : SerializeEvidence(report),
            EvidenceInputCount = report?.Evidence?.TotalInputs ?? 0,
            CorroboratedCount = report?.Evidence?.FullyCorroboratedCount ?? 0,
            ConflictCount = report?.Evidence?.ConflictCount ?? 0,
            UnresolvedConflictCount = report?.Evidence?.UnresolvedConflictCount ?? 0,
            Outcome = report?.Outcome ?? InvestigationOutcome.InsufficientEvidence
        };
    }

    // Stages 3-6 — analyze, parse, validate, enforce
    public LlmEvidenceAnalysisReport Analyze(
        string scenarioName,
        InvestigationReport? report,
        ILlmEvidenceAnalyzer analyzer)
    {
        if (scenarioName is null) throw new ArgumentNullException(nameof(scenarioName));
        if (report is null) throw new ArgumentNullException(nameof(report));
        if (analyzer is null) throw new ArgumentNullException(nameof(analyzer));

        var context = BuildContext(scenarioName, report);

        var analysis = new LlmEvidenceAnalysisReport
        {
            ScenarioName = scenarioName,
            AnalyzerName = analyzer.AnalyzerName,
            Context = context
        };

        // Stage 3 — analyzer contract (deterministic in-Core: scripted)
        var rawOutput = analyzer.Analyze(context);

        // Stage 4 — deterministic claim parsing
        analysis.Claims = ParseClaims(rawOutput);

        // Stages 5-6 — validate + enforce per claim
        foreach (var claim in analysis.Claims)
        {
            // Stage 6 — structural refusal BEFORE validation
            if (IsRepairFlavored(claim))
            {
                analysis.Verdicts.Add(new LlmClaimVerdict
                {
                    Claim = claim,
                    Decision = LlmClaimDecision.Refused,
                    Reason = "fix/repair claim refused structurally: the Core executes no repair. " +
                             NoRepairEnforcementService.BoundaryReference
                });
                continue;
            }

            // Stage 5 — evidence-to-claim validation (BF-14.9 single truth)
            var request = new EvidenceClaimRequest
            {
                ClaimType = MapClaimType(claim.Kind),
                ClaimText = claim.ClaimText,
                TargetKey = claim.TargetKey,
                ConfidenceScore = claim.ClaimedConfidence,
                DistinctSourceCount = claim.ClaimedDistinctSources,
                UnresolvedHighConflicts = claim.ClaimedHighConflicts
            };
            var coreVerdict = _enforcement.ValidateClaim(request);

            analysis.Verdicts.Add(new LlmClaimVerdict
            {
                Claim = claim,
                Decision = coreVerdict.Acceptance == ClaimAcceptance.Accepted
                    ? LlmClaimDecision.Accepted
                    : LlmClaimDecision.Rejected,
                Reason = coreVerdict.Reason,
                CoreVerdict = coreVerdict
            });
        }

        return Finalize(analysis);
    }

    // ---------- internals ----------

    // Stage 4 — contract: KIND|target|confidence|sources|highConflicts|text
    // TargetKey MAY contain pipes (StableKeys do: M|Asm|FQN) - only the
    // kind (first field) and the last four fields are positional;
    // everything between them is the target.
    public List<LlmClaim> ParseClaims(string? rawOutput)
    {
        var claims = new List<LlmClaim>();
        if (string.IsNullOrWhiteSpace(rawOutput)) return claims;

        foreach (var rawLine in rawOutput.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;

            var parts = line.Split('|');
            if (parts.Length < 6) continue;   // malformed lines are skipped honestly

            if (!TryMapKind(parts[0].Trim(), out var kind)) continue;
            if (!double.TryParse(parts[^4].Trim(), out var confidence)) continue;
            if (!int.TryParse(parts[^3].Trim(), out var sources)) continue;
            if (!int.TryParse(parts[^2].Trim(), out var highConflicts)) continue;

            var target = string.Join("|", parts[1..^4]).Trim();

            claims.Add(new LlmClaim
            {
                Kind = kind,
                TargetKey = string.IsNullOrWhiteSpace(target) ? null : target,
                ClaimedConfidence = confidence,
                ClaimedDistinctSources = sources,
                ClaimedHighConflicts = highConflicts,
                ClaimText = parts[^1].Trim(),
                RawLine = line
            });
        }
        return claims;
    }

    // Stage 6 — structural refusal: FixSuggestion KIND is always refused,
    // and repair-flavored TEXT is refused regardless of kind or evidence.
    private static bool IsRepairFlavored(LlmClaim claim) =>
        claim.Kind == LlmClaimKind.FixSuggestion
        || RepairTokens.Any(token => claim.ClaimText.Contains(token, StringComparison.OrdinalIgnoreCase));

    private static bool TryMapKind(string text, out LlmClaimKind kind)
    {
        switch (text.ToUpperInvariant())
        {
            case "SUSPICION": kind = LlmClaimKind.Suspicion; return true;
            case "ROOTCAUSE": kind = LlmClaimKind.RootCauseHypothesis; return true;
            case "FIX": kind = LlmClaimKind.FixSuggestion; return true;
            case "OTHER": kind = LlmClaimKind.Other; return true;
            default: kind = LlmClaimKind.Other; return false;
        }
    }

    private static CoreClaimType MapClaimType(LlmClaimKind kind) => kind switch
    {
        LlmClaimKind.RootCauseHypothesis => CoreClaimType.RootCause,
        _ => CoreClaimType.CandidateSuspicion
    };

    private static LlmEvidenceAnalysisReport Finalize(LlmEvidenceAnalysisReport report)
    {
        report.TotalClaims = report.Verdicts.Count;
        report.AcceptedClaims = report.Verdicts.Count(v => v.Decision == LlmClaimDecision.Accepted);
        report.RejectedClaims = report.Verdicts.Count(v => v.Decision == LlmClaimDecision.Rejected);
        report.RefusedClaims = report.Verdicts.Count(v => v.Decision == LlmClaimDecision.Refused);
        return report;
    }
}

/// <summary>
/// Stage 3 contract: real LLM analyzers live OUTSIDE the Core
/// (network calls, prompts, API keys - forbidden here, BF-14.9).
/// </summary>
public interface ILlmEvidenceAnalyzer
{
    string AnalyzerName { get; }

    /// <summary>Raw analyzer output; the line contract is enforced by ParseClaims.</summary>
    string Analyze(EvidenceAnalysisContext context);
}

/// <summary>
/// Deterministic in-Core research analyzer: echoes a fixed, caller-built
/// output for the given context. No randomness, no network.
/// </summary>
public class ScriptedLlmAnalyzer : ILlmEvidenceAnalyzer
{
    private readonly string _output;

    public ScriptedLlmAnalyzer(string output)
    {
        if (output is null) throw new ArgumentNullException(nameof(output));
        _output = output;
    }

    public string AnalyzerName => "ScriptedLLM";

    public string Analyze(EvidenceAnalysisContext context) => _output;
}