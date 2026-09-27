using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class LlmEvidenceAnalysisTests
{
    private static readonly DateTime T0 = new(2026, 9, 20, 10, 0, 0, DateTimeKind.Utc);

    private static readonly FailureIdentityInput Failure = new()
    {
        TestIdentity = "ISCM.Tests.EventLogSizeCheck_Test",
        FailureCategory = "Assertion:Equality"
    };

    private static readonly List<FailureLocation> PrimaryLocation = new()
    {
        new() { FilePath = "Check.cs", LineNumber = 42, MethodName = "Evaluate", IsPrimary = true }
    };

    private static InvestigationReport BuildReport()
    {
        var raw = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,    RawStrength = 0.9, TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs", ObservedAtUtc = T0 },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Coverage, RawStrength = 0.7, TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs", ObservedAtUtc = T0.AddMinutes(5) }
        };

        return new InvestigationReportService().Investigate(Failure, PrimaryLocation, raw);
    }

    // Stage 1 — evidence serialization from the real Core report
    [Fact]
    public void SerializeEvidence_ContainsCoreMarkers()
    {
        var report = BuildReport();

        var json = new LlmEvidenceAnalysisService().SerializeEvidence(report);

        json.Should().Contain("\"Outcome\"");
        json.Should().Contain("M|ISCM|Check.Evaluate()");
        json.Should().Contain("CORE STOPS HERE");
    }

    // Stage 2 — bounded context construction
    [Fact]
    public void BuildContext_CarriesSizesAndOutcome()
    {
        var report = BuildReport();

        var context = new LlmEvidenceAnalysisService().BuildContext("Ctx", report);

        context.ScenarioName.Should().Be("Ctx");
        context.EvidenceInputCount.Should().Be(2);
        context.CorroboratedCount.Should().Be(1);
        context.ConflictCount.Should().Be(0);
        context.Outcome.Should().Be(InvestigationOutcome.Complete);
        context.EvidenceJson.Should().NotBeEmpty();
    }

    // Stage 4 — deterministic parsing: happy path + malformed lines skipped
    [Fact]
    public void ParseClaims_ContractLines_ParsedMalformedSkipped()
    {
        var raw = string.Join("\n",
            "SUSPICION|M|R|Compute()|0.5|1|0|element looks suspicious",
            "garbage line without pipes",
            "ROOTCAUSE|M|R|Compute()|0.85|3|0|root cause is Compute",
            "BROKEN|M|R|x|not-a-number|1|0|bad payload",
            "");

        var claims = new LlmEvidenceAnalysisService().ParseClaims(raw);

        claims.Should().HaveCount(2);
        claims[0].Kind.Should().Be(LlmClaimKind.Suspicion);
        claims[0].TargetKey.Should().Be("M|R|Compute()");
        claims[0].ClaimedConfidence.Should().Be(0.5);
        claims[1].Kind.Should().Be(LlmClaimKind.RootCauseHypothesis);
        claims[1].ClaimedConfidence.Should().Be(0.85);
        claims[1].ClaimedDistinctSources.Should().Be(3);
    }

    // Stage 4 — StableKeys contain pipes: target fields are re-joined
    [Fact]
    public void ParseClaims_PipeInTargetKey_Reconstructed()
    {
        var raw = "SUSPICION|M|ISCM|Check.Evaluate()|0.6|1|0|evaluate path suspicious";

        var claims = new LlmEvidenceAnalysisService().ParseClaims(raw);

        claims.Should().ContainSingle();
        claims[0].TargetKey.Should().Be("M|ISCM|Check.Evaluate()");
        claims[0].ClaimedConfidence.Should().Be(0.6);
        claims[0].ClaimedDistinctSources.Should().Be(1);
        claims[0].ClaimText.Should().Be("evaluate path suspicious");
    }

    // Stage 5+6 — full pipeline: accepted / rejected / refused mix
    [Fact]
    public void Analyze_MixedClaims_AcceptedRejectedRefused()
    {
        var report = BuildReport();
        var raw = string.Join("\n",
            "SUSPICION|M|ISCM|Check.Evaluate()|0.6|1|0|evaluate path suspicious",   // accepted
            "ROOTCAUSE|M|ISCM|Check.Evaluate()|0.4|1|0|root cause claimed",           // rejected (unsupported)
            "FIX|M|ISCM|Check.Evaluate()|0.9|5|0|just change the operator",           // refused (FixSuggestion KIND)
            "SUSPICION||0|0|0|blind guess with no evidence"                            // rejected (no signal)
        );
        var analyzer = new ScriptedLlmAnalyzer(raw);

        var analysis = new LlmEvidenceAnalysisService().Analyze("Mixed", report, analyzer);

        analysis.AnalyzerName.Should().Be("ScriptedLLM");
        analysis.TotalClaims.Should().Be(4);
        analysis.AcceptedClaims.Should().Be(1);
        analysis.RejectedClaims.Should().Be(2);
        analysis.RefusedClaims.Should().Be(1);

        var accepted = analysis.Verdicts.First(v => v.Decision == LlmClaimDecision.Accepted);
        accepted.CoreVerdict.Should().NotBeNull();
        accepted.UncertaintyPreserved.Should().BeFalse();

        var rejected = analysis.Verdicts.First(v => v.Decision == LlmClaimDecision.Rejected);
        rejected.UncertaintyPreserved.Should().BeTrue();

        var refused = analysis.Verdicts.First(v => v.Decision == LlmClaimDecision.Refused);
        refused.CoreVerdict.Should().BeNull();               // never reached validation
        refused.Reason.Should().Contain("refused structurally");
        refused.UncertaintyPreserved.Should().BeTrue();
    }

    // Stage 6 — every repair flavor is refused regardless of evidence strength
    [Fact]
    public void Analyze_RepairFlavoredClaims_AllRefused()
    {
        var report = BuildReport();
        var raw = string.Join("\n",
            "FIX|M|R|A()|0.9|5|0|patch the condition",
            "OTHER|M|R|B()|0.9|5|0|please repair this method",
            "OTHER|M|R|C()|0.9|5|0|apply an autofix here");

        var analysis = new LlmEvidenceAnalysisService().Analyze("Refuse", report, new ScriptedLlmAnalyzer(raw));

        analysis.RefusedClaims.Should().Be(3);
        analysis.AcceptedClaims.Should().Be(0);
        analysis.Verdicts.Should().OnlyContain(v => v.UncertaintyPreserved);
    }

    // Stage 5 — LLM overclaiming is capped by real evidence (rejected, kept honest)
    [Fact]
    public void Analyze_OverconfidentRootCause_RejectedWithUncertaintyPreserved()
    {
        var report = BuildReport();
        var raw = "ROOTCAUSE|M|ISCM|Check.Evaluate()|0.99|1|0|totally the cause, trust me";

        var analysis = new LlmEvidenceAnalysisService().Analyze("Overclaim", report, new ScriptedLlmAnalyzer(raw));

        analysis.RejectedClaims.Should().Be(1);
        analysis.Verdicts[0].Reason.Should().Contain("unsupported root cause");
        analysis.Verdicts[0].UncertaintyPreserved.Should().BeTrue();
    }

    // Graceful degradation — empty/malformed output, no throw
    [Fact]
    public void Analyze_EmptyAndMalformed_GracefulEmptyReport()
    {
        var report = BuildReport();

        var empty = new LlmEvidenceAnalysisService().Analyze("E1", report, new ScriptedLlmAnalyzer(""));
        var garbage = new LlmEvidenceAnalysisService().Analyze("E2", report, new ScriptedLlmAnalyzer("###\n@@@\n"));

        empty.TotalClaims.Should().Be(0);
        garbage.TotalClaims.Should().Be(0);
        garbage.Claims.Should().BeEmpty();
    }

    // Contract violations fail fast
    [Fact]
    public void Analyze_NullArguments_Throw()
    {
        var report = BuildReport();

        Action nullReport = () => new LlmEvidenceAnalysisService().Analyze("S", null!, new ScriptedLlmAnalyzer("SUSPICION||0.5|1|0|x"));
        Action nullAnalyzer = () => new LlmEvidenceAnalysisService().Analyze("S", report, null!);
        Action nullSerialize = () => new LlmEvidenceAnalysisService().SerializeEvidence(null!);

        nullReport.Should().Throw<ArgumentNullException>();
        nullAnalyzer.Should().Throw<ArgumentNullException>();
        nullSerialize.Should().Throw<ArgumentNullException>();
    }

    // Research contract markers (serializable disclaimer - 15.7 lesson)
    [Fact]
    public void Report_CarriesResearchMarkers()
    {
        LlmEvidenceAnalysisReport.DisclaimerText.Should().Contain("EXPERIMENTAL");
        LlmEvidenceAnalysisReport.DisclaimerText.Should().Contain("validated");
        LlmEvidenceAnalysisReport.DisclaimerText.Should().Contain("refused");
        LlmEvidenceAnalysisService.ResearchBoundaryNote.Should().Contain("proposals, not findings");
    }
}