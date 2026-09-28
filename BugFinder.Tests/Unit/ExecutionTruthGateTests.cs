using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

/// <summary>
/// H-03.9: Execution Truth Gate — the closing gate of H-03.
/// Each stage runs the full chain end-to-end: launch (3.1) -> classify
/// (3.2) -> cancel (3.3) -> discover (3.4) -> ingest TRX (3.5) ->
/// ingest domain (3.6) -> provenance (3.7) -> normalize (3.8).
/// Exit gate: "No downstream analysis is allowed to consume an
/// execution result whose process truth or artifact provenance is unknown."
/// Zero production code — orchestration only.
/// </summary>
public class ExecutionTruthGateTests
{
    private readonly ProcessExecutionService _process = new();
    private readonly TrxIngestionService _trx = new();
    private readonly TestTargetDiscoveryService _discovery = new();

    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    private static string WriteTrx(string xml)
    {
        var path = Path.Combine(Path.GetTempPath(), $"gate-{Guid.NewGuid():N}.trx");
        File.WriteAllText(path, xml);
        return path;
    }

    private const string FailedTrx = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Times start="2026-09-27T12:00:00.000Z" finish="2026-09-27T12:00:30.000Z" />
  <TestDefinitions>
    <UnitTest name="NS.MyClass.EventLogSizeCheck_Test" id="guid-1" storage="d:\out\ISCM.Tests.dll">
      <TestMethod className="NS.MyClass" name="EventLogSizeCheck_Test" codeBase="d:\out\ISCM.Tests.dll" />
    </UnitTest>
  </TestDefinitions>
  <Results>
    <UnitTestResult executionId="guid-1" testName="EventLogSizeCheck_Test"
                    outcome="Failed" startTime="2026-09-27T12:00:05.000Z"
                    endTime="2026-09-27T12:00:07.500Z" duration="00:00:02.500" />
  </Results>
</TestRun>
""";

    private const string EmptyResultsTrx = """
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <TestDefinitions />
  <Results />
</TestRun>
""";

    // ================================================================
    // Stage 3.9.1 — non-zero exit code survives to the normalized outcome
    // (KBF-01-001 pin: the fabrication fix, end-to-end)
    // ================================================================

    [Fact]
    public async Task Gate_3_9_1_NonZeroExitCode_SurvivesToNormalizedOutcome()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var processResult = await _process.ExecuteRawAsync(input, new[] { "/c", "exit", "42" });

        processResult.Kind.Should().Be(ServiceResultKind.Success);
        var evidence = processResult.Value!;
        evidence.ExitCode.Should().Be(42);   // KBF-01-001: REAL code, not fabricated 0

        var classification = ExitCodeClassifier.Classify(new ExitCodeSignal
        {
            ExitCode = evidence.ExitCode,
            ArtifactProduced = false
        });

        var outcome = OutcomeNormalization.FromProcess(evidence, classification);

        outcome.Layer.Should().Be(OutcomeLayer.Infrastructure);
        outcome.RawSourceOutcome.Should().Be("42");   // THE truth assertion
        outcome.ExecutionStatus.Should().Be(ExecutionStatus.TestHostFailed);
    }

    // ================================================================
    // Stage 3.9.2 — build failure: exit 1 without artifact
    // ================================================================

    [Fact]
    public void Gate_3_9_2_BuildFailure_Exit1WithoutArtifact()
    {
        var evidence = new ProcessExecutionEvidence
        {
            ExitCode = 1,
            ResultArtifactPath = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.trx")
        };

        var classification = ExitCodeClassifier.ClassifyFromEvidence(evidence);
        classification.Status.Should().Be(ExecutionStatus.BuildFailed);

        var outcome = OutcomeNormalization.FromProcess(evidence, classification);
        outcome.ExecutionStatus.Should().Be(ExecutionStatus.BuildFailed);
        outcome.Layer.Should().Be(OutcomeLayer.Infrastructure);
    }

    // ================================================================
    // Stage 3.9.3 — discovery failure: documented exit-code limitation +
    // the honest artifact-level signal (NoResults)
    // ================================================================

    [Fact]
    public void Gate_3_9_3_DiscoveryFailure_ExplicitAtArtifactLevel()
    {
        // exit-code limitation pinned (documented v1): zero tests exit 0
        ExitCodeClassifier.Classify(new ExitCodeSignal
        {
            ExitCode = 0,
            ArtifactProduced = true
        }).Status.Should().Be(ExecutionStatus.Executed);

        // artifact-level truth: a TRX with zero UnitTestResults is
        // explicitly NoResults — the discovery-failure signal lives HERE
        var trxPath = WriteTrx(EmptyResultsTrx);
        var report = new TrxIngestionService().Ingest(trxPath);

        report.Status.Should().Be(TrxIngestionStatus.NoResults);
        report.Records.Should().BeEmpty();
        report.Reason.Should().Contain("zero UnitTestResult");
    }

    // ================================================================
    // Stage 3.9.4 — cancellation: kill tree, evidence, no fabricated success
    // ================================================================

    [Fact]
    public async Task Gate_3_9_4_Cancellation_PartialEvidence_NoFabricatedSuccess()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        using var cts = new CancellationTokenSource();
        var launchTask = _process.ExecuteRawAsync(
            input, new[] { "/c", "ping", "127.0.0.1", "-n", "30" }, cts.Token);

        await Task.Delay(500);   // let the process start
        cts.Cancel();

        var result = await launchTask;

        result.Kind.Should().Be(ServiceResultKind.Partial);   // not Success!
        result.HasValue.Should().BeTrue();

        var evidence = result.Value!;
        evidence.TerminatedByCancellation.Should().BeTrue();
        evidence.ProcessId.Should().NotBeNull();
        evidence.EndUtc.Should().NotBeNull();

        // orphan prevention: the captured PID must be dead
        var pid = evidence.ProcessId!.Value;
        var gone = false;
        for (var attempt = 0; attempt < 20 && !gone; attempt++)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                gone = p.HasExited;
            }
            catch (ArgumentException)
            {
                gone = true;
            }
            if (!gone) await Task.Delay(100);
        }
        gone.Should().BeTrue("cancelled child processes must be terminated, not orphaned");
    }

    // ================================================================
    // Stage 3.9.5 — multi-assembly: discovery yields explicit targets,
    // each target drives its OWN launch input (no hard-coded default)
    // ================================================================

    [Fact]
    public void Gate_3_9_5_MultiAssembly_DiscoveryFeedsDistinctLaunchInputs()
    {
        const string CSharpSdk = "9A19103F-16F7-4668-BE54-9A1E7A4F7556";
        var dir = Path.Combine(Path.GetTempPath(), $"gate-sln-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(Path.Combine(dir, "ISCM.Tests"));
        Directory.CreateDirectory(Path.Combine(dir, "ISCM.BugFinder.Tests"));

        var slnPath = Path.Combine(dir, "Probe.sln");
        File.WriteAllLines(slnPath, new[]
        {
            "Microsoft Visual Studio Solution File, Format Version 12.00",
            $"Project(\"{{{CSharpSdk}}}\") = \"ISCM.Tests\", \"ISCM.Tests\\ISCM.Tests.csproj\", \"{{22222222-2222-2222-2222-222222222222}}\"",
            "EndProject",
            $"Project(\"{{{CSharpSdk}}}\") = \"ISCM.BugFinder.Tests\", \"BugFinder.Tests\\BugFinder.Tests.csproj\", \"{{55555555-5555-5555-5555-555555555555}}\"",
            "EndProject"
        });

        var report = _discovery.Discover(slnPath);

        report.TestProjects.Should().HaveCount(2);

        // each discovered target produces a DISTINCT launch input —
        // no hard-coded default anywhere in the chain
        var launchInputs = report.TestProjects.Select(t => new ProcessLaunchInput
        {
            WorkingDirectory = dir,
            TestProjectPath = t.ProjectFilePath,
            ResultArtifactPath = $"TestResults/{t.ProjectName}.trx"
        }).ToList();

        launchInputs.Select(i => i.TestProjectPath).Should().BeInAscendingOrder();
        launchInputs.Select(i => i.TestProjectPath).Distinct().Should().HaveCount(2);

        // and each target's args carry ITS OWN project path
        foreach (var input in launchInputs)
        {
            var args = _process.BuildArguments(input.TestProjectPath, input.ResultArtifactPath);
            args.Should().Contain(input.TestProjectPath);
        }

        try { Directory.Delete(dir, recursive: true); } catch { }
    }

    // ================================================================
    // Stage 3.9.6 — timestamp fidelity: OS + XML timestamps, not UtcNow
    // ================================================================

    [Fact]
    public async Task Gate_3_9_6_TimestampFidelity_OsAndXml_NotFabricated()
    {
        // A) process timestamps are OS-observed and coherent
        var before = DateTimeOffset.UtcNow.AddSeconds(-5);
        var processResult = await _process.ExecuteRawAsync(
            new ProcessLaunchInput
            {
                WorkingDirectory = Path.GetTempPath(),
                Executable = "cmd.exe"
            },
            new[] { "/c", "exit", "0" });

        var evidence = processResult.Value!;
        evidence.StartUtc!.Value.Should().BeOnOrAfter(before);
        evidence.EndUtc!.Value.Should().BeOnOrAfter(evidence.StartUtc.Value);
        evidence.Duration!.Value.Should().BeLessOrEqualTo(TimeSpan.FromSeconds(30));

        // B) TRX timestamps are the XML-observed values (EXACT match —
        //    impossible if the engine had used UtcNow)
        var trxPath = WriteTrx(FailedTrx);
        var report = _trx.Ingest(trxPath);

        var record = report.Records.Single();
        record.StartedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:05.000Z"));
        record.CompletedUtc.Should().Be(DateTimeOffset.Parse("2026-09-27T12:00:07.500Z"));
        record.Duration.Should().Be(TimeSpan.FromSeconds(2.5));
    }

    // ================================================================
    // Full-pipeline composition — TRX ingest → normalize → H-02 signature
    // (proves the H-03 outputs feed the H-02 identity pipeline live)
    // ================================================================

    [Fact]
    public void Gate_FullPipeline_TrxIngestion_ToNormalizedOutcome_ToSignature()
    {
        var trxPath = WriteTrx(FailedTrx);
        var report = _trx.Ingest(trxPath);

        var normalized = OutcomeNormalization.FromTrx(report.Records.Single());

        normalized.Layer.Should().Be(OutcomeLayer.Test);
        normalized.TestStatus.Should().Be(TestSemanticStatus.Failed);
        normalized.RawSourceOutcome.Should().Be("Failed");

        // H-03.5 normalization: storage path is SLASH-NORMALIZED by design
        // (JoinKeyNormalization contract from H-01.7) - backslash input
        // becomes forward-slash identity.
        normalized.Identity!.AssemblyName.Should().Be("d:/out/ISCM.Tests.dll");

        // H-02 signature pipeline consumes the normalized material LIVE
        var derivation = new FailureSignatureService().Generate(normalized.Material!);
        derivation.Signature.Value.Should().MatchRegex(@"^FS-[0-9a-f]{64}$");
        derivation.FailureId.Value.Should().StartWith("F-");
    }

    // The gate statement — disclaimers still carried by the terminal contract
    [Fact]
    public void Gate_CoreBoundary_StillEnforced()
    {
        InvestigationReport.CoreBoundaryText.Should().Contain("CORE STOPS HERE");
        InvestigationReport.CoreBoundaryText.Should().Contain("No patch");
    }
}