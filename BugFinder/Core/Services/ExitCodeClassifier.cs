using System;
using System.IO;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-03.2: Exit Code Classifier.
/// Classify(signal): pure policy — exit code + artifact flag in,
/// ExecutionStatus + reason out. No I/O, no text matching.
/// ClassifyFromEvidence: convenience overload over ProcessExecutionEvidence
/// (H-03.1) that checks the artifact on disk — the honest "did the
/// process actually produce its result artifact" signal.
///
/// FABRICATED-SUCCESS REJECTION (3.2.6): a null exit code maps to
/// Unavailable in every combination — the pre-hardening engine reported
/// ExitCode=0 "for ingestion" (KBF-01-001); that path is now closed.
/// </summary>
public static class ExitCodeClassifier
{
    public static ExitCodeClassification Classify(ExitCodeSignal signal)
    {
        if (signal is null) throw new ArgumentNullException(nameof(signal));

        // 3.2.6 — no reported exit code: process truth unknown.
        // Even a produced artifact does not make an aborted run "Executed".
        if (signal.ExitCode is null)
            return new ExitCodeClassification
            {
                Status = ExecutionStatus.Unavailable,
                Reason = "process never reported an exit code (H-03.2.6: " +
                         "fabricated success rejected, regardless of artifact)"
            };

        var code = signal.ExitCode.Value;

        if (code == 0)
            return new ExitCodeClassification
            {
                Status = ExecutionStatus.Executed,
                Reason = "exit code 0: process completed successfully"
            };

        if (code == 1)
            return signal.ArtifactProduced
                ? new ExitCodeClassification
                {
                    Status = ExecutionStatus.Executed,
                    Reason = "exit code 1 with result artifact: tests ran; " +
                             "failures are test-level and live in the artifact (3.2.2)"
                }
                : new ExitCodeClassification
                {
                    Status = ExecutionStatus.BuildFailed,
                    Reason = "exit code 1 without result artifact: tests never ran " +
                             "(build failed before execution — 3.2.3)"
                };

        // abnormal non-zero codes (crash signals, host failures, ...)
        return signal.ArtifactProduced
            ? new ExitCodeClassification
            {
                Status = ExecutionStatus.Executed,
                Reason = $"abnormal exit code {code} with result artifact: tests ran " +
                         "(anomaly noted for H-03.7 provenance)"
            }
            : new ExitCodeClassification
            {
                Status = ExecutionStatus.TestHostFailed,
                Reason = $"abnormal exit code {code} without result artifact: " +
                         "host-level failure (3.2.5; v1 conservative — refined by " +
                         "structured output in H-03.5/3.6)"
            };
    }

    /// <summary>
    /// Evidence overload: artifact signal = the TRX actually exists on disk
    /// (audit KBF-01-003: artifact-based, not text-based).
    /// </summary>
    public static ExitCodeClassification ClassifyFromEvidence(ProcessExecutionEvidence evidence)
    {
        if (evidence is null) throw new ArgumentNullException(nameof(evidence));

        var artifactProduced = !string.IsNullOrWhiteSpace(evidence.ResultArtifactPath)
                               && File.Exists(evidence.ResultArtifactPath);

        return Classify(new ExitCodeSignal
        {
            ExitCode = evidence.ExitCode,
            ArtifactProduced = artifactProduced
        });
    }
}