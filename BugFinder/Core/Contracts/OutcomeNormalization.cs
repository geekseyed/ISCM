using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-03.8: Result Normalization Contract
/// (audit KBF-01-011: test-level, domain-level and application-level
/// statuses were not represented by one discriminated result model;
/// semantic status conversion was incomplete — downstream consumers
/// compared unlike result types).
///
/// ONE MODEL with an explicit LAYER: downstream consumers see which
/// layer produced the outcome and read only that layer's status field —
/// cross-layer comparison is structurally impossible.
///
/// 3.8.5 Preserve source semantics: RawSourceOutcome keeps the source
/// vocabulary verbatim (e.g. TRX "Passed", CheckStatus "Fail").
///
/// LINKED CONTRACTS:
///   ExecutionStatus (H-01.4) — infrastructure layer truth
///   TestSemanticStatus (H-01.4) — canonical test semantics
///   CheckStatus (Domain vocabulary) — domain semantics preserved as-is
///   FailureSignatureMaterial (H-02.1) — material adoptable per outcome
/// </summary>
public enum OutcomeLayer
{
    /// <summary>Test-runner level (TRX record).</summary>
    Test,

    /// <summary>Domain evaluation level (CheckStatus vocabulary).</summary>
    Domain,

    /// <summary>Process/infrastructure level (dotnet test host itself).</summary>
    Infrastructure
}

public sealed class NormalizedFailureOutcome
{
    public OutcomeLayer Layer { get; init; }

    // Stage 3.8.1 — process truth (Infrastructure layer; also attached to
    // Test/Domain outcomes as the run context when evidence exists)
    public ExecutionStatus? ExecutionStatus { get; init; }

    // Stage 3.8.2 — test semantic status (Test layer only)
    public TestSemanticStatus? TestStatus { get; init; }

    // Stage 3.8.3 — domain status (Domain layer only)
    public CheckStatus? DomainStatus { get; init; }

    /// <summary>Identity of the failing test (Test/Domain layers).</summary>
    public FailureIdentity? Identity { get; init; }

    /// <summary>Stage 3.8.5 — source vocabulary verbatim.</summary>
    public string? RawSourceOutcome { get; init; }

    /// <summary>Source artifact identity (TRX path / console evidence ref).</summary>
    public string? SourceArtifact { get; init; }

    /// <summary>Material for the H-02 signature pipeline (when adoptable).</summary>
    public FailureSignatureMaterial? Material { get; init; }

    /// <summary>Guard: exactly one semantic layer is primary.</summary>
    public bool HasSemanticStatus =>
        Layer == OutcomeLayer.Test && TestStatus.HasValue
        || Layer == OutcomeLayer.Domain && DomainStatus.HasValue
        || Layer == OutcomeLayer.Infrastructure;
}

/// <summary>Projection contract namespace for H-03.8.</summary>
public static class OutcomeNormalization
{
    /// <summary>
    /// Stage 3.8.2 — TRX record → Test layer. Uses H-01.4 projection;
    /// unknown definitions preserved honestly (test name fallback).
    /// </summary>
    public static NormalizedFailureOutcome FromTrx(TrxTestRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));

        var semantic = record.Outcome switch
        {
            "Passed" => TestSemanticStatus.Passed,
            "Failed" => TestSemanticStatus.Failed,
            "NotExecuted" => TestSemanticStatus.Skipped,
            "Skipped" => TestSemanticStatus.Skipped,
            _ => TestSemanticStatus.Unknown
        };

        return new NormalizedFailureOutcome
        {
            Layer = OutcomeLayer.Test,
            TestStatus = semantic,
            Identity = new FailureIdentity
            {
                TestName = record.TestFullName,
                ClassName = ExtractClassName(record.TestFullName),
                AssemblyName = record.AssemblyPath   // real storage path (H-03.5)
            },
            RawSourceOutcome = record.Outcome,
            Material = FailureSignatureMaterialFactory.FromDomainEvaluation(
                new NormalizedEvaluationResult
                {
                    SubControlId = string.Empty,     // TRX has no domain vocabulary
                    Status = semantic == TestSemanticStatus.Failed
                        ? CheckStatus.Fail
                        : CheckStatus.Unknown,
                    Reason = $"TRX {record.Outcome}",
                    SourceTestId = record.TestFullName
                })
        };
    }

    /// <summary>
    /// Stage 3.8.3 — domain record → Domain layer (CheckStatus preserved
    /// verbatim — no conversion into test vocabulary).
    /// </summary>
    public static NormalizedFailureOutcome FromDomain(DomainEvaluationRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));

        return new NormalizedFailureOutcome
        {
            Layer = OutcomeLayer.Domain,
            DomainStatus = record.Status,
            Identity = new FailureIdentity
            {
                TestName = record.SourceTestId ?? string.Empty
            },
            RawSourceOutcome = record.RawStatus ?? record.Status.ToString(),
            Material = FailureSignatureMaterialFactory.FromDomainEvaluation(
                record.ToNormalizedEvaluationResult())
        };
    }

    /// <summary>
    /// Stage 3.8.1/3.8.4 — process evidence → Infrastructure layer
    /// (exit code classification via H-03.2 — real code, no fabrication).
    /// </summary>
    public static NormalizedFailureOutcome FromProcess(
        ProcessExecutionEvidence evidence, ExitCodeClassification classification)
    {
        if (evidence is null) throw new ArgumentNullException(nameof(evidence));
        if (classification is null) throw new ArgumentNullException(nameof(classification));

        return new NormalizedFailureOutcome
        {
            Layer = OutcomeLayer.Infrastructure,
            ExecutionStatus = classification.Status,
            RawSourceOutcome = evidence.ExitCode?.ToString() ?? "null",
            SourceArtifact = evidence.ResultArtifactPath
        };
    }

    /// <summary>"NS.Class.Test" → class part (no fabrication when absent).</summary>
    private static string ExtractClassName(string fullName)
    {
        if (string.IsNullOrWhiteSpace(fullName)) return string.Empty;
        var lastDot = fullName.LastIndexOf('.');
        return lastDot <= 0 ? string.Empty : fullName[..lastDot];
    }
}