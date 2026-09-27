using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

/// <summary>
/// H-01.9: Contract Gate — the closing gate of H-01.
/// Individual sub-phase tests proved each contract in isolation; this
/// gate proves them AS ONE SYSTEM (H-01 exit gate: "every downstream
/// service must consume one canonical identity/state contract; no phase
/// may define its own competing semantics").
/// </summary>
public class ContractGateTests
{
    private const string Hex64 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
    private const string Hex32 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
    private const string AuditedHead = "86e0b257cc0d4c957f0120a1ea201ed8d3ebc067";

    // ================================================================
    // Stage 1.9.1 — Contract compilation / inventory gate
    // ================================================================

    [Fact]
    public void Gate_1_9_1_ContractInventory_AllTypesPresent()
    {
        var assembly = typeof(BaselineManifest).Assembly;
        const string ns = "ISCM.BugFinder.Core.Contracts";

        string[] expected =
        {
            // H-01.1 baseline identity
            "BaselineManifest", "BaselineManifestInput", "BaselineMatchStatus", "BaselineVerificationReport",
            // H-01.2 identifiers (all ten + family)
            "FailureSignature", "FailureId", "FailureInstanceId", "EvidenceId",
            "ExecutionSessionId", "InvestigationId", "RevisionId",
            "SymbolKey", "TargetKey", "LocationId", "TargetKeyKind", "PrefixedHexIdentifier",
            // H-01.3 schema & version
            "CoreSchema", "SchemaFamily", "SchemaReadStatus", "SchemaEnvelope", "SchemaReadResult`1",
            // H-01.4 outcome states
            "EvidenceState", "Measured`1", "ExecutionStatus", "TestSemanticStatus",
            "TestSemanticStatusProjection", "DomainEvaluationSemantics", "FailureSemantics",
            "UncertaintySemantics",
            // H-01.5 external advisory boundary
            "ExternalAdvisoryClaimType", "ExternalAdvisoryRequest", "ExternalAdvisoryVerdict",
            // H-01.6 canonical projections
            "FailureIdentityProjection", "SourceLocationProjection",
            "SuspiciousTargetProjection", "FailureRecordProjection",
            // H-01.7 typed joins
            "JoinKeyNormalization", "TypedJoinEntry", "TypedJoinIndex",
            // H-01.8 common result
            "ServiceResultKind", "ServiceDiagnostic", "ServiceResult`1", "ServiceResult"
        };

        var missing = expected
            .Where(name => assembly.GetType($"{ns}.{name}") is null)
            .ToList();

        missing.Should().BeEmpty("every H-01 contract type must exist (compilation gate)");
    }

    // ================================================================
    // Stage 1.9.2 — serialization round-trip gates
    // ================================================================

    [Fact]
    public void Gate_1_9_2_BaselineManifest_RoundTrip()
    {
        var service = new BaselineManifestService();
        var manifest = service.Build(new BaselineManifestInput
        {
            RepositoryId = "geekseyed/ISCM",
            Branch = "diagnostics-debug1/phase01-contract-repair",
            CommitSha = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
            RecordedAtUtc = DateTimeOffset.UtcNow,
            AuditedHeadSha = AuditedHead,
            SolutionName = "ISCM.sln",
            TargetFramework = "net8.0",
            TestFramework = "xunit 2.7.0",
            TestSdkVersion = "17.9.0",
            TestCommand = "dotnet test",
            PassedCount = 191,
            FailedCount = 0,
            SkippedCount = 0,
            ExecutionDuration = TimeSpan.FromSeconds(40)
        });

        var restored = service.Deserialize(service.Serialize(manifest))!;

        restored.CommitSha.Should().Be(manifest.CommitSha);
        restored.AuditedHeadSha.Should().Be(AuditedHead);
        restored.PassedCount.Should().Be(191);
    }

    [Fact]
    public void Gate_1_9_2_Identifiers_SurviveSchemaEnvelope_RoundTrip()
    {
        // The integration gate: typed identifiers (1.2) travel through the
        // versioned envelope (1.3) and re-parse as the same identities.
        var schema = new SchemaVersionService();
        var payload = new Dictionary<string, string>
        {
            ["failureSignature"] = $"FS-{Hex64}",
            ["evidenceId"] = $"EV-{Hex32}",
            ["session"] = $"ES-{Hex32}",
            ["revision"] = AuditedHead
        };

        var json = schema.Write(payload, SchemaFamily.Evidence);
        var read = schema.Read<Dictionary<string, string>>(json, SchemaFamily.Evidence);

        read.IsUsable.Should().BeTrue();

        FailureSignature.TryParse(read.Payload!["failureSignature"], out var fs).Should().BeTrue();
        EvidenceId.TryParse(read.Payload["evidenceId"], out var ev).Should().BeTrue();
        ExecutionSessionId.TryParse(read.Payload["session"], out var session).Should().BeTrue();
        RevisionId.TryParse(read.Payload["revision"], out var rev).Should().BeTrue();

        fs!.Value.Should().Be($"FS-{Hex64}");
        ev!.Value.Should().Be($"EV-{Hex32}");
        session!.Value.Should().Be($"ES-{Hex32}");
        rev!.Value.Should().Be(AuditedHead);
    }

    [Fact]
    public void Gate_1_9_2_ServiceDiagnostic_Serializable()
    {
        var result = ServiceResult<int>.DiagnosticError(
            new InvalidOperationException("boom"), "GateService");

        var json = System.Text.Json.JsonSerializer.Serialize(result.Diagnostics);
        var restored = System.Text.Json.JsonSerializer
            .Deserialize<ServiceDiagnostic[]>(json)!;

        restored.Should().ContainSingle(d =>
            d.Message == "boom"
            && d.ExceptionTypeName == "System.InvalidOperationException"
            && d.Source == "GateService");
    }

    // ================================================================
    // Stage 1.9.3 — version compatibility gate
    // ================================================================

    [Fact]
    public void Gate_1_9_3_VersionCompatibility_AllOutcomes_Explicit()
    {
        var writer = new SchemaVersionService();
        var v1Json = writer.Write(new Dictionary<string, string> { ["k"] = "v" }, SchemaFamily.History);

        // current reader: Current
        new SchemaVersionService().Read<Dictionary<string, string>>(v1Json, SchemaFamily.History)
            .Status.Should().Be(SchemaReadStatus.Current);

        // older reader without migrator: explicit RequiresMigration (never empty)
        var older = new SchemaVersionService(currentVersionOverride: 2);
        older.Read<Dictionary<string, string>>(v1Json, SchemaFamily.History)
            .Status.Should().Be(SchemaReadStatus.RequiresMigration);

        // older reader with migrator: Migrated
        older.RegisterMigrator(SchemaFamily.History, 1, p => p);
        older.Read<Dictionary<string, string>>(v1Json, SchemaFamily.History)
            .Status.Should().Be(SchemaReadStatus.Migrated);

        // newer document than reader: explicit NewerThanReader (never guessed)
        var patched = v1Json.Replace("\"SchemaVersion\": 1", "\"SchemaVersion\": 50");
        new SchemaVersionService().Read<Dictionary<string, string>>(patched, SchemaFamily.History)
            .Status.Should().Be(SchemaReadStatus.NewerThanReader);
    }

    // Single Truth: every version stamp derives from one constant
    [Fact]
    public void Gate_1_9_3_SchemaVersion_SingleTruth()
    {
        BaselineManifest.CurrentSchemaVersion.Should().Be(CoreSchema.CurrentVersion);
        new SchemaVersionService().CurrentVersion.Should().Be(CoreSchema.CurrentVersion);
    }

    // ================================================================
    // Stage 1.9.4 — forbidden-claim gate
    // ================================================================

    [Fact]
    public void Gate_1_9_4_RootCause_NeverAccepted_AtAnyEvidenceLevel()
    {
        var service = new NoRepairEnforcementService();

        foreach (var (confidence, sources, conflicts) in new[]
                 {
                     (0.99, 99, 0), (0.8, 3, 0), (1.0, 100, 0), (0.5, 1, 1)
                 })
        {
            var verdict = service.ValidateClaim(new EvidenceClaimRequest
            {
                ClaimType = CoreClaimType.RootCause,
                ClaimText = "cause claim",
                TargetKey = "T",
                ConfidenceScore = confidence,
                DistinctSourceCount = sources,
                UnresolvedHighConflicts = conflicts
            });

            verdict.Acceptance.Should().Be(ClaimAcceptance.Rejected,
                $"confidence={confidence}, sources={sources}: RootCause is never a Core claim (H-01.5.4)");
            verdict.UncertaintyPreserved.Should().BeTrue();
        }
    }

    [Fact]
    public void Gate_1_9_4_LlmClaims_FixRefused_RootCauseRejected()
    {
        var raw = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack, RawStrength = 0.9,
                TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs" }
        };
        var report = new InvestigationReportService().Investigate(
            new FailureIdentityInput { TestIdentity = "T1", FailureCategory = "Assertion" }, null, raw);

        var analysis = new LlmEvidenceAnalysisService().Analyze("Gate",
            report, new ScriptedLlmAnalyzer(string.Join("\n",
                "FIX|M|ISCM|Check.Evaluate()|0.99|99|0|patch it",
                "ROOTCAUSE|M|ISCM|Check.Evaluate()|0.99|99|0|definitely the cause")));

        analysis.RefusedClaims.Should().Be(1);      // fix: structural refusal
        analysis.RejectedClaims.Should().Be(1);     // root cause: contract rejection
        analysis.AcceptedClaims.Should().Be(0);
        analysis.Verdicts.Should().OnlyContain(v => v.UncertaintyPreserved);
    }

    [Fact]
    public void Gate_1_9_4_OperationGate_ForbiddenOperations_StillBlocked()
    {
        var service = new NoRepairEnforcementService();

        foreach (var op in new[]
                 {
                     CoreOperation.ModifySource, CoreOperation.GeneratePatch,
                     CoreOperation.ApplyPatch, CoreOperation.AutoFix,
                     CoreOperation.ExecuteRemediation
                 })
        {
            service.ValidateOperation(op).Verdict.Should().Be(CoreOperationVerdict.Blocked);
        }

        // historical thresholds remain compile-time dead (H-01.5.4 guard)
        typeof(NoRepairEnforcementService)
            .GetField("RootCauseMinConfidence")!
            .GetCustomAttributes(false)
            .Should().Contain(a => a is ObsoleteAttribute);
    }

    // ================================================================
    // Stage 1.9.5 — canonical identity consistency gate
    // ================================================================

    [Fact]
    public void Gate_1_9_5_FailureIdentity_ProjectionRoundTrip_IsExact()
    {
        var identity = new FailureIdentity
        {
            AssemblyName = "ASM",
            ClassName = "NS.MyClass",
            TestName = "MyTest"
        };

        var input = FailureIdentityProjection.ToInput(identity,
            failureCategory: "Assertion:Equality");

        var restored = FailureIdentityProjection.FromInput(input);

        restored.ToFullString().Should().Be(identity.ToFullString());
        input.FailureCategory.Should().Be("Assertion:Equality");
    }

    [Fact]
    public void Gate_1_9_5_Location_BothViews_YieldOneTypedIdentity()
    {
        var canonical = new SourceLocation { FilePath = "Calc.cs", LineNumber = 42 };
        var chainView = SourceLocationProjection.ToChainView(canonical, isPrimary: true);

        var fromCanonical = SourceLocationProjection.ToLocationId(canonical);
        var fromChain = SourceLocationProjection.ToLocationId(chainView);

        fromCanonical.Should().Be(fromChain);
        fromCanonical!.ToString().Should().Be("LOC|Calc.cs|L42");
    }

    [Fact]
    public void Gate_1_9_5_TargetKey_ConsistentAcrossAllFiveSuspiciousViews()
    {
        const string element = "Calc.cs:Evaluate:42";

        var keys = new[]
        {
            SuspiciousTargetProjection.TargetKeyOf(new RankedFaultCandidate { ElementId = element }),
            SuspiciousTargetProjection.TargetKeyOf(new EvidenceRankedCandidate { ElementId = element }),
            SuspiciousTargetProjection.TargetKeyOf(new SuspiciousLocation { ElementId = element }),
            SuspiciousTargetProjection.TargetKeyOf(new ExperimentalSuspiciousness { ElementId = element }),
            SuspiciousTargetProjection.TargetKeyOf(new CorrelatedTarget { TargetKey = element })
        };

        keys.Distinct().Should().ContainSingle();
        keys[0].Value.Should().Be(element);
    }

    // H-01.4 + H-01.8 vocabulary alignment: Missing and Unavailable are
    // DISTINCT in both Measured and ServiceResult - one language, no drift
    [Fact]
    public void Gate_1_9_5_StateVocabulary_MeasuredAndServiceResult_Aligned()
    {
        // zero vs missing vs unavailable stay distinct in Measured
        Measured<int>.Observed(0).State.Should().Be(EvidenceState.Observed);
        Measured<int>.Missing().State.Should().Be(EvidenceState.Missing);
        Measured<int>.Unavailable().State.Should().Be(EvidenceState.Unavailable);

        // ServiceResult maps onto the same vocabulary
        ServiceResult<int>.Success(0).State.Should().Be(EvidenceState.Observed);
        ServiceResult<int>.Unavailable("no collector").State.Should().Be(EvidenceState.Unavailable);
        ServiceResult<int>.Corrupt("bad artifact").State.Should().Be(EvidenceState.Corrupt);

        // and the uncertainty rule agrees across both
        UncertaintySemantics.RequiresUncertaintyReporting(EvidenceState.Missing).Should().BeTrue();
        UncertaintySemantics.RequiresUncertaintyReporting(EvidenceState.Observed).Should().BeFalse();
    }

    // X-005 join-safety: Fusion, Consistency and Conflict agree on group
    // membership for padded/separator-variant keys (H-01.7 single truth)
    [Fact]
    public void Gate_1_9_5_GroupKeyAgreement_AcrossFusionConsistencyConflict()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,    RawStrength = 0.8, TargetSymbolKey = " M|R|Compute() " },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Coverage, RawStrength = 0.6, TargetSymbolKey = "M|R|Compute()" }
        };

        var fused = new EvidenceFusionService().Fuse(inputs);
        var consistency = new EvidenceConsistencyService().Evaluate(inputs, fused);
        var conflicts = new ConflictAnalysisService().Analyze(inputs, consistency);

        var fusionKey = fused.Items.Single().TargetKey;
        fusionKey.Should().Be("M|R|Compute()");

        consistency.Targets.Single().TargetKey.Should().Be(fusionKey);
        consistency.Targets.Single().CrossSource.Should().Be(CrossSourceStatus.Corroborated);
        conflicts.Conflicts.Should().BeEmpty();   // same key => corroborated, no split
    }

    // Join diagnostics stay clean on a well-formed contract surface
    [Fact]
    public void Gate_1_9_5_JoinDiagnostics_CleanOnWellFormedKeys()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,    RawStrength = 0.9, TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs" },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Coverage, RawStrength = 0.7, TargetSymbolKey = "M|ISCM|Check.Evaluate()", TargetFilePath = "Check.cs" }
        };

        var fused = new EvidenceFusionService().Fuse(inputs);

        fused.JoinDiagnostics.Should().BeEmpty();
    }
}