using System;
using System.IO;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class ExitCodeClassifierTests
{
    private static ExitCodeClassification Classify(int? code, bool artifact) =>
        ExitCodeClassifier.Classify(new ExitCodeSignal
        {
            ExitCode = code,
            ArtifactProduced = artifact
        });

    // ---------- Stage 3.2.1/3.2.2 — full signal matrix ----------

    [Theory]
    [InlineData(0, true, ExecutionStatus.Executed)]        // all passed
    [InlineData(0, false, ExecutionStatus.Executed)]        // completed (zero-tests case)
    [InlineData(1, true, ExecutionStatus.Executed)]        // 3.2.2: test-level failures
    [InlineData(1, false, ExecutionStatus.BuildFailed)]     // 3.2.3: never ran
    [InlineData(42, true, ExecutionStatus.Executed)]        // ran; anomaly noted
    [InlineData(42, false, ExecutionStatus.TestHostFailed)]  // 3.2.5: abnormal, no artifact
    [InlineData(-1073741819, false, ExecutionStatus.TestHostFailed)] // crash signal
    [InlineData(null, true, ExecutionStatus.Unavailable)]     // 3.2.6
    [InlineData(null, false, ExecutionStatus.Unavailable)]     // 3.2.6
    public void Classify_FullSignalMatrix(int? code, bool artifact, ExecutionStatus expected)
    {
        Classify(code, artifact).Status.Should().Be(expected);
    }

    // ---------- Stage 3.2.6 — fabricated success rejected ----------

    [Fact]
    public void Classify_NullExitCode_NeverExecuted_EvenWithArtifact()
    {
        var classification = Classify(null, artifact: true);

        classification.Status.Should().NotBe(ExecutionStatus.Executed);
        classification.Reason.Should().Contain("fabricated success rejected");
    }

    // Every classification carries a non-empty reason
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(null, false)]
    [InlineData(42, false)]
    public void Classify_AlwaysCarriesReason(int? code, bool artifact)
    {
        Classify(code, artifact).Reason.Should().NotBeNullOrWhiteSpace();
    }

    // ---------- Evidence overload (artifact on disk) ----------

    [Fact]
    public void ClassifyFromEvidence_ArtifactExists_Executed()
    {
        var artifact = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), $"gate-{Guid.NewGuid():N}.trx");
        System.IO.File.WriteAllText(artifact, "<trx/>");
        try
        {
            var evidence = new ProcessExecutionEvidence
            {
                ExitCode = 1,
                ResultArtifactPath = artifact
            };

            var classification = ExitCodeClassifier.ClassifyFromEvidence(evidence);

            classification.Status.Should().Be(ExecutionStatus.Executed);
            classification.Reason.Should().Contain("test-level");
        }
        finally
        {
            System.IO.File.Delete(artifact);
        }
    }

    [Fact]
    public void ClassifyFromEvidence_ArtifactMissing_BuildFailed()
    {
        var evidence = new ProcessExecutionEvidence
        {
            ExitCode = 1,
            ResultArtifactPath = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.trx")
        };

        var classification = ExitCodeClassifier.ClassifyFromEvidence(evidence);

        classification.Status.Should().Be(ExecutionStatus.BuildFailed);
    }

    [Fact]
    public void ClassifyFromEvidence_NullArtifactPath_Unavailable()
    {
        var evidence = new ProcessExecutionEvidence
        {
            ExitCode = null,
            ResultArtifactPath = string.Empty
        };

        var classification = ExitCodeClassifier.ClassifyFromEvidence(evidence);

        classification.Status.Should().Be(ExecutionStatus.Unavailable);
    }

    // Contract violations fail fast
    [Fact]
    public void Classify_NullSignal_Throws()
    {
        Action act = () => ExitCodeClassifier.Classify(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ClassifyFromEvidence_NullEvidence_Throws()
    {
        Action act = () => ExitCodeClassifier.ClassifyFromEvidence(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // v1 limitation — documented honestly (DiscoveryFailed not exit-code-visible)
    [Fact]
    public void Classifier_Documentation_DiscoveryFailure_NotExitCodeVisible()
    {
        // dotnet test with zero tests exits 0 -> indistinguishable from
        // success by exit code alone; DiscoveryFailed requires structured
        // discovery output (H-03.6). This test pins the documented reality:
        var classification = Classify(0, artifact: false);
        classification.Status.Should().Be(ExecutionStatus.Executed);
    }
}