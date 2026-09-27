using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class InvestigationClaimContractTests
{
    private readonly NoRepairEnforcementService _service = new();

    private static EvidenceClaimRequest Claim(
        CoreClaimType type, double confidence = 0.9, int sources = 5, int highConflicts = 0) => new()
        {
            ClaimType = type,
            ClaimText = "claim",
            TargetKey = "T",
            ConfidenceScore = confidence,
            DistinctSourceCount = sources,
            UnresolvedHighConflicts = highConflicts
        };

    // H-01.5.1/1.5.2 — the two allowed claim shapes still work
    [Fact]
    public void Observation_AlwaysAccepted()
    {
        var verdict = _service.ValidateClaim(Claim(CoreClaimType.Observation, confidence: 0));
        verdict.Acceptance.Should().Be(ClaimAcceptance.Accepted);
    }

    [Fact]
    public void CandidateSuspicion_WithEvidence_Accepted()
    {
        var verdict = _service.ValidateClaim(Claim(CoreClaimType.CandidateSuspicion, confidence: 0.6));
        verdict.Acceptance.Should().Be(ClaimAcceptance.Accepted);
    }

    // H-01.5.4 — THE contract: RootCause is NEVER accepted by the Core,
    // even with maximal evidence (KBF-14-009 fix)
    [Fact]
    public void RootCause_MaximalEvidence_StillRejected()
    {
        var verdict = _service.ValidateClaim(
            Claim(CoreClaimType.RootCause, confidence: 0.99, sources: 99, highConflicts: 0));

        verdict.Acceptance.Should().Be(ClaimAcceptance.Rejected);
        verdict.UncertaintyPreserved.Should().BeTrue();
        verdict.Reason.Should().Contain("never accepted by the Core");
        verdict.Reason.Should().Contain("H-01.5.4");
    }

    [Theory]
    [InlineData(0.99, 99, 0)]
    [InlineData(1.0, 100, 0)]
    [InlineData(0.8, 3, 0)]
    public void RootCause_PreviouslyAcceptedCombinations_NowRejected(
        double confidence, int sources, int highConflicts)
    {
        var verdict = _service.ValidateClaim(
            Claim(CoreClaimType.RootCause, confidence, sources, highConflicts));

        verdict.Acceptance.Should().Be(ClaimAcceptance.Rejected);
    }

    // H-01.5.4 — historical thresholds are compile-time dead (obsolete-as-error).
    // String literals, NOT nameof: the constants are [Obsolete(error:true)],
    // so even nameof would fail compilation (CS0619) - which IS the guard working.
    [Fact]
    public void RootCauseThresholds_AreMarkedObsoleteAndUnused()
    {
        var type = typeof(NoRepairEnforcementService);

        type.GetField("RootCauseMinConfidence")!
            .GetCustomAttributes(false)
            .Should().Contain(a => a is ObsoleteAttribute);

        type.GetField("RootCauseMinDistinctSources")!
            .GetCustomAttributes(false)
            .Should().Contain(a => a is ObsoleteAttribute);
    }

    // H-01.5.5 — SuggestedAction fields no longer exist on Core models
    [Fact]
    public void CoreConclusionModels_CarryNoSuggestedAction()
    {
        typeof(RootCauseHypothesis)
            .GetProperty("SuggestedAction").Should().BeNull();
        typeof(LocalizedRootCause)
            .GetProperty("SuggestedActions").Should().BeNull();
    }

    // H-01.5.6 — advisory types: non-Core claim kinds flagged
    [Fact]
    public void ExternalAdvisory_NonCoreClaimTypes_Flagged()
    {
        var rootCause = new ExternalAdvisoryRequest
        {
            ClaimType = ExternalAdvisoryClaimType.RootCauseInterpretation,
            ClaimText = "interpreted cause",
            SourceConclusionReference = "INV-x",
            AdvisorySource = "LLM-advisory"
        };
        var action = new ExternalAdvisoryRequest
        {
            ClaimType = ExternalAdvisoryClaimType.SuggestedAction,
            ClaimText = "suggested change",
            SourceConclusionReference = "INV-x",
            AdvisorySource = "human-review"
        };

        new ExternalAdvisoryVerdict { Request = rootCause, IsAdvisoryOnly = true }
            .IsNonCoreClaimType.Should().BeTrue();
        new ExternalAdvisoryVerdict { Request = action, IsAdvisoryOnly = true }
            .IsNonCoreClaimType.Should().BeTrue();
    }

    [Fact]
    public void ExternalAdvisory_CoreClaimTypes_NotFlaggedAsNonCore()
    {
        var observation = new ExternalAdvisoryVerdict
        {
            Request = new ExternalAdvisoryRequest
            {
                ClaimType = ExternalAdvisoryClaimType.Observation,
                ClaimText = "fact restatement",
                SourceConclusionReference = "INV-x",
                AdvisorySource = "dashboard"
            },
            IsAdvisoryOnly = true
        };

        observation.IsNonCoreClaimType.Should().BeFalse();
    }

    // H-01.5.7 — LLM refusal path (15.6) must stay alive over the new contract
    [Fact]
    public void LlmFixClaims_StillRefused_ThroughNewContract()
    {
        var report = BuildMinimalReport();
        var raw = "FIX|M|R|A()|0.9|5|0|patch it";
        var analysis = new LlmEvidenceAnalysisService()
            .Analyze("Gate", report, new ScriptedLlmAnalyzer(raw));

        analysis.RefusedClaims.Should().Be(1);
        analysis.Verdicts[0].Reason.Should().Contain("refused structurally");
    }

    [Fact]
    public void LlmRootCauseClaims_RejectedThroughNewContract()
    {
        var report = BuildMinimalReport();
        var raw = "ROOTCAUSE|M|ISCM|Check.Evaluate()|0.99|9|0|surely the cause";
        var analysis = new LlmEvidenceAnalysisService()
            .Analyze("Gate", report, new ScriptedLlmAnalyzer(raw));

        analysis.RejectedClaims.Should().Be(1);
        analysis.Verdicts[0].CoreVerdict!.Reason.Should().Contain("never accepted by the Core");
    }

    private static InvestigationReport BuildMinimalReport()
    {
        var raw = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack, RawStrength = 0.9,
                TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs" }
        };
        var failure = new FailureIdentityInput { TestIdentity = "T1", FailureCategory = "Assertion" };
        return new InvestigationReportService().Investigate(failure, null, raw);
    }
}