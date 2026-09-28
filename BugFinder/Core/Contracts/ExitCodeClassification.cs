namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-03.2: Exit Code Integrity — input/output shapes for classifying the
/// REAL process exit code (captured by H-03.1) into an ExecutionStatus
/// (H-01.4).
///
/// SIGNALS (audit KBF-01-003: classification is based on exit code +
/// result artifacts + process state — NEVER on fragile stderr text
/// matching like the legacy "Failed!" check):
///   ExitCode         - the real captured code (null = never reported)
///   ArtifactProduced - did the process actually write its result
///                      artifact (TRX)?  The single most decisive
///                      signal: tests that RAN produce artifacts.
///
/// v1 RULES (conservative, documented):
///   null                 -> Unavailable   (3.2.6: fabricated success rejected —
///                                          NEVER Executed, even with an artifact)
///   0                    -> Executed
///   1   + artifact       -> Executed      (test-level failures live in the TRX — 3.2.2)
///   1   without artifact -> BuildFailed   (tests never ran — 3.2.3)
///   N!=0/1 without artifact -> TestHostFailed (abnormal code — 3.2.5)
///   N!=0/1 with artifact    -> Executed    (tests ran; anomaly noted)
///
/// v1 LIMITATION (documented): DiscoveryFailed (H-01.4) is not
/// distinguishable from exit codes alone (dotnet test exits 0 with zero
/// tests) - it requires structured discovery output (H-03.6) and is
/// never emitted by this classifier.
/// </summary>
public sealed class ExitCodeSignal
{
    public int? ExitCode { get; init; }
    public bool ArtifactProduced { get; init; }
}

public sealed class ExitCodeClassification
{
    public ExecutionStatus Status { get; init; }
    public string Reason { get; init; } = string.Empty;
}