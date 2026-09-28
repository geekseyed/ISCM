using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-03.1: Process Launch Evidence — everything KNOWN about the launch
/// and lifetime of one process execution (audit KBF-01-001/002/007).
///
/// TRUTH RULES:
///   - ExitCode is the REAL process exit code, never a fabricated 0
///     (KBF-01-001 fix at the evidence level; classification in H-03.2).
///   - StartUtc/EndUtc are OBSERVED process timestamps converted to UTC
///     when the OS provides them; null means "not captured" — never
///     replaced by DateTime.UtcNow (KBF-01-007 fix; X-003).
///   - ProcessId captured from the live process (H-03.1.4).
///   - Configuration flows from the caller; the service invents nothing.
///
/// H-03.3.4: TerminatedByCancellation marks executions ended by an
/// observed cancellation (the child tree was killed and reaped).
/// </summary>
public sealed class ProcessExecutionEvidence
{
    // H-03.1.4 — OS process id
    public int? ProcessId { get; init; }

    // H-03.1.5/3.1.6 — observed lifetime (UTC, OS-provided)
    public DateTimeOffset? StartUtc { get; init; }
    public DateTimeOffset? EndUtc { get; init; }

    /// <summary>Real process exit code; null when the process never reported one.</summary>
    public int? ExitCode { get; init; }

    /// <summary>Executable that was launched (e.g. "dotnet").</summary>
    public string Executable { get; init; } = string.Empty;

    /// <summary>The exact argument list as constructed (audit copy).</summary>
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();

    /// <summary>Validated working directory.</summary>
    public string WorkingDirectory { get; init; } = string.Empty;

    /// <summary>The test target this process ran (explicit — no hard-coded default).</summary>
    public string TestProjectPath { get; init; } = string.Empty;

    /// <summary>TRX path the process was instructed to write (artifact of H-03.5).</summary>
    public string ResultArtifactPath { get; init; } = string.Empty;

    /// <summary>Observed lifetime; null when timestamps are incomplete.</summary>
    public TimeSpan? Duration => StartUtc.HasValue && EndUtc.HasValue
        ? EndUtc.Value - StartUtc.Value
        : null;

    /// <summary>H-03.3.4 — terminated by an observed cancellation (kill + reap).</summary>
    public bool TerminatedByCancellation { get; init; }
}

/// <summary>H-03.1.1/3.1.2/3.1.3 — validated launch input.</summary>
public sealed class ProcessLaunchInput
{
    public string WorkingDirectory { get; init; } = string.Empty;
    public string TestProjectPath { get; init; } = string.Empty;
    public string? ResultArtifactPath { get; init; }
    public string Executable { get; init; } = "dotnet";
}