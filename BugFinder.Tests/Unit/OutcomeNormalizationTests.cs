using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;

namespace ISCM.Tests.Unit.BugFinder;

public class OutcomeNormalizationTests
{
    private static TrxTestRecord TrxRecord(
        string outcome = "Failed",
        string fullName = "NS.MyClass.MyTest",
        string storage = "d:\\out\\ISCM.Tests.dll") => new()
        {
            ExecutionId = "guid-1",
            TestName = fullName.Split('.').Last(),
            TestFullName = fullName,
            AssemblyPath = storage,
            Outcome = outcome
        };

    private static DomainEvaluationRecord DomainRecord(
        CheckStatus status = CheckStatus.Fail,
        string subControl = "EVL-001.4",
        string? sourceTest = "EventLogSizeCheck_Test") => new()
        {
            SubControlId = subControl,
            Status = status,
            RawStatus = status.ToString(),
            Reason = "expected 512 MB, actual 128 MB",
            Expected = "512",
            Actual = "128",
            SourceTestId = sourceTest
        };

    // Stage 3.8.2 — TRX → Test layer with semantic projection
    [Theory]
    [InlineData("Passed", TestSemanticStatus.Passed)]
    [InlineData("Failed", TestSemanticStatus.Failed)]
    [InlineData("NotExecuted", TestSemanticStatus.Skipped)]
    [InlineData("Weird", TestSemanticStatus.Unknown)]
    public void FromTrx_SemanticProjection(string trxOutcome, TestSemanticStatus expected)
    {
        var outcome = OutcomeNormalization.FromTrx(TrxRecord(trxOutcome));

        outcome.Layer.Should().Be(OutcomeLayer.Test);
        outcome.TestStatus.Should().Be(expected);
        outcome.DomainStatus.Should().BeNull();        // cross-layer impossible
        outcome.RawSourceOutcome.Should().Be(trxOutcome);   // 3.8.5 preserved
    }

    // 3.8.5 — real assembly identity preserved (KBF-01-006 continuity)
    [Fact]
    public void FromTrx_RealAssemblyPath_Preserved()
    {
        var outcome = OutcomeNormalization.FromTrx(
            TrxRecord(storage: "d:\\other\\Other.Tests.dll"));

        outcome.Identity!.AssemblyName.Should().Be("d:\\other\\Other.Tests.dll");
    }

    [Fact]
    public void FromTrx_Material_Present()
    {
        var outcome = OutcomeNormalization.FromTrx(TrxRecord());
        outcome.Material.Should().NotBeNull();
        outcome.Material!.TestIdentity.TestName.Should().Be("NS.MyClass.MyTest");
    }

    // Stage 3.8.3 — domain vocabulary preserved verbatim
    [Fact]
    public void FromDomain_CheckStatus_PreservedVerbatim()
    {
        var outcome = OutcomeNormalization.FromDomain(DomainRecord(CheckStatus.Fail));

        outcome.Layer.Should().Be(OutcomeLayer.Domain);
        outcome.DomainStatus.Should().Be(CheckStatus.Fail);
        outcome.TestStatus.Should().BeNull();          // cross-layer impossible
        outcome.RawSourceOutcome.Should().Be("Fail");
    }

    // H-01.4.9 — NotApplicable domain status stays NotApplicable (never Fail)
    [Fact]
    public void FromDomain_NotApplicable_StaysNotApplicable()
    {
        var outcome = OutcomeNormalization.FromDomain(
            DomainRecord(CheckStatus.NotApplicable));

        outcome.DomainStatus.Should().Be(CheckStatus.NotApplicable);
    }

    // H-02 adoption — domain material carries all six fields
    [Fact]
    public void FromDomain_Material_CarriesAllFields()
    {
        var outcome = OutcomeNormalization.FromDomain(DomainRecord());

        outcome.Material!.SubControlId.Should().Be("EVL-001.4");
        outcome.Material.DomainStatus.Should().Be(CheckStatus.Fail);
        outcome.Material.RawMessage.Should().Be("expected 512 MB, actual 128 MB");
    }

    // Stage 3.8.1/3.8.4 — process evidence → Infrastructure layer
    [Fact]
    public void FromProcess_BuildFailed_InfrastructureLayer()
    {
        var evidence = new ProcessExecutionEvidence
        {
            ExitCode = 1,
            ResultArtifactPath = @"C:\missing\probe.trx"   // artifact absent
        };
        var classification = ExitCodeClassifier.ClassifyFromEvidence(evidence);

        var outcome = OutcomeNormalization.FromProcess(evidence, classification);

        outcome.Layer.Should().Be(OutcomeLayer.Infrastructure);
        outcome.ExecutionStatus.Should().Be(ExecutionStatus.BuildFailed);
        outcome.TestStatus.Should().BeNull();
        outcome.DomainStatus.Should().BeNull();
        outcome.RawSourceOutcome.Should().Be("1");
    }

    [Fact]
    public void FromProcess_Executed_InfrastructureLayer()
    {
        var evidence = new ProcessExecutionEvidence { ExitCode = 0 };
        var classification = ExitCodeClassifier.Classify(
            new ExitCodeSignal { ExitCode = 0, ArtifactProduced = true });

        var outcome = OutcomeNormalization.FromProcess(evidence, classification);

        outcome.ExecutionStatus.Should().Be(ExecutionStatus.Executed);
        outcome.RawSourceOutcome.Should().Be("0");
    }

    // X-002 — engine diagnostic error vs domain failure stays distinct
    [Fact]
    public void FromProcess_Unavailable_UnknownLayer()
    {
        var evidence = new ProcessExecutionEvidence { ExitCode = null };
        var classification = ExitCodeClassifier.Classify(
            new ExitCodeSignal { ExitCode = null, ArtifactProduced = true });

        var outcome = OutcomeNormalization.FromProcess(evidence, classification);

        outcome.ExecutionStatus.Should().Be(ExecutionStatus.Unavailable);
    }

    // Guard — layer/semantic pairing is consistent
    [Fact]
    public void Outcome_HasSemanticStatus_LayerConsistent()
    {
        OutcomeNormalization.FromTrx(TrxRecord()).HasSemanticStatus.Should().BeTrue();
        OutcomeNormalization.FromDomain(DomainRecord()).HasSemanticStatus.Should().BeTrue();

        var evidence = new ProcessExecutionEvidence { ExitCode = 0 };
        var classification = ExitCodeClassifier.Classify(
            new ExitCodeSignal { ExitCode = 0, ArtifactProduced = true });
        OutcomeNormalization.FromProcess(evidence, classification)
            .HasSemanticStatus.Should().BeTrue();
    }

    // KBF-01-011 — THE exit-gate scenario: three layers, three outcomes,
    // one model — cross-layer comparison structurally impossible
    [Fact]
    public void ThreeLayers_OneModel_CrossLayerComparisonImpossible()
    {
        var testOutcome = OutcomeNormalization.FromTrx(TrxRecord("Failed"));
        var domainOutcome = OutcomeNormalization.FromDomain(DomainRecord(CheckStatus.Fail));
        var infraOutcome = OutcomeNormalization.FromProcess(
            new ProcessExecutionEvidence { ExitCode = 1 },
            ExitCodeClassifier.Classify(new ExitCodeSignal { ExitCode = 1, ArtifactProduced = false }));

        testOutcome.Layer.Should().Be(OutcomeLayer.Test);
        domainOutcome.Layer.Should().Be(OutcomeLayer.Domain);
        infraOutcome.Layer.Should().Be(OutcomeLayer.Infrastructure);

        // each layer exposes ONLY its own status field
        testOutcome.DomainStatus.Should().BeNull();
        testOutcome.ExecutionStatus.Should().BeNull();
        domainOutcome.TestStatus.Should().BeNull();
        infraOutcome.TestStatus.Should().BeNull();
    }

    // Contract violations fail fast
    [Fact]
    public void Projections_NullArguments_Throw()
    {
        Action nullTrx = () => OutcomeNormalization.FromTrx(null!);
        Action nullDomain = () => OutcomeNormalization.FromDomain(null!);
        Action nullEvidence = () => OutcomeNormalization.FromProcess(
            null!, ExitCodeClassifier.Classify(new ExitCodeSignal()));
        Action nullClassification = () => OutcomeNormalization.FromProcess(
            new ProcessExecutionEvidence(), null!);

        nullTrx.Should().Throw<ArgumentNullException>();
        nullDomain.Should().Throw<ArgumentNullException>();
        nullEvidence.Should().Throw<ArgumentNullException>();
        nullClassification.Should().Throw<ArgumentNullException>();
    }
}