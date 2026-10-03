using System.Diagnostics;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-05.1: Git Command Service — the single structured execution layer
/// for every git invocation in Core (KBF-10-001 fix).
///
/// PATTERN SOURCE (documented reuse): process handling follows the
/// H-03.1 ProcessExecutionService pattern — ArgumentList quoting, OS-
/// recorded timestamps, REAL exit code, cancellation kills the child
/// tree and waits (H-03.3 continuity). DELIBERATE DIFFERENCE: git
/// output must be RETURNED for parsing, while H-03.1 evidence is
/// artifact-based by contract — so GitCommandEvidence carries
/// StdOut/StdErr directly. H-03 files are untouched.
///
/// VERDICT SEMANTICS (H-01.8):
///   invalid INPUT (verb/arguments/working directory) = fail-fast
///   ArgumentException/InvalidOperationException (meaningless input is
///   not absence — project rule);
///   a COMPLETED but FAILED command = evidence with Succeeded=false —
///   never an exception, never fabricated success;
///   infra failure (process did not start) = InvalidOperationException.
///
/// READ-ONLY ENFORCEMENT: only whitelisted verbs run (5.1.1); mutating
/// capabilities (push/checkout/reset/...) are structurally unreachable
/// (Strict Core Boundary — completed in H-05.3).
/// </summary>
public class GitCommandService
{
    public const string Executable = "git";

    /// <summary>Synchronous entry point (current regression pipeline is sync).</summary>
    public GitCommandEvidence Run(GitCommandRequest request, CancellationToken cancellationToken = default) =>
        RunAsync(request, cancellationToken).GetAwaiter().GetResult();

    public async Task<GitCommandEvidence> RunAsync(
        GitCommandRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        // Stage 5.1.1 — read-only verb whitelist
        if (string.IsNullOrWhiteSpace(request.Verb))
            throw new ArgumentException("Git verb is required.", nameof(request));
        if (!GitCommandSafety.IsVerbAllowed(request.Verb))
            throw new InvalidOperationException(
                $"Git verb '{request.Verb}' is outside the read-only whitelist " +
                "(H-05.1.1 / KBF-10-001) — mutating capabilities are unreachable from Core.");

        // Stage 5.1.2 — structured arguments + global option guard
        GitCommandSafety.ValidateArguments(request.Arguments);

        // Stage 5.1.3 — working directory must exist
        if (string.IsNullOrWhiteSpace(request.WorkingDirectory))
            throw new ArgumentException("Working directory (repository root) is required.", nameof(request));
        var workingDirectory = Path.GetFullPath(request.WorkingDirectory);
        if (!Directory.Exists(workingDirectory))
            throw new ArgumentException(
                $"Working directory does not exist: '{workingDirectory}'.", nameof(request));

        var arguments = new List<string> { request.Verb };
        arguments.AddRange(request.Arguments);

        // Stage 5.1.5 — cancellation observed BEFORE launch: evidence without a process
        if (cancellationToken.IsCancellationRequested)
            return new GitCommandEvidence
            {
                Verb = request.Verb,
                Purpose = request.Purpose,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                TerminatedByCancellation = true
            };

        var startInfo = new ProcessStartInfo
        {
            FileName = Executable,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);   // quoting owned by the OS layer — no interpolation

        var output = new System.Text.StringBuilder();
        var error = new System.Text.StringBuilder();

        using var process = new Process { StartInfo = startInfo };
        process.OutputDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) output.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) error.AppendLine(e.Data); };

        if (!process.Start())
            throw new InvalidOperationException("git process failed to start (infrastructure failure).");
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var processId = SafeInt(() => process.Id);
        var startUtc = SafeDate(() => new DateTimeOffset(process.StartTime.ToUniversalTime()));

        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // H-03.3 continuity — terminate the child tree and wait
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            try { await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false); } catch { }

            return new GitCommandEvidence
            {
                Verb = request.Verb,
                Purpose = request.Purpose,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                ProcessId = processId,
                StartUtc = startUtc,
                EndUtc = SafeDate(() => new DateTimeOffset(process.ExitTime.ToUniversalTime())),
                ExitCode = SafeInt(() => process.ExitCode),
                TerminatedByCancellation = true,
                StdOut = output.ToString(),
                StdErr = error.ToString()
            };
        }

        process.WaitForExit();   // flush the async readers (standard pattern)

        return new GitCommandEvidence
        {
            Verb = request.Verb,
            Purpose = request.Purpose,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            ProcessId = processId,
            StartUtc = startUtc,
            EndUtc = SafeDate(() => new DateTimeOffset(process.ExitTime.ToUniversalTime())),
            ExitCode = SafeInt(() => process.ExitCode),
            TerminatedByCancellation = false,
            StdOut = output.ToString(),
            StdErr = error.ToString()
        };
    }

    /// <summary>
    /// Legacy-compatibility verdict helper: preserves the exact previous
    /// contract (throw on non-zero exit WITH stderr) on top of evidence.
    /// </summary>
    public static void ThrowIfFailed(GitCommandEvidence evidence)
    {
        if (evidence is null) throw new ArgumentNullException(nameof(evidence));
        if (!evidence.Succeeded && !string.IsNullOrWhiteSpace(evidence.StdErr))
            throw new InvalidOperationException($"Git command failed: {evidence.StdErr.Trim()}");
    }

    private static int? SafeInt(Func<int> accessor)
    {
        try { return accessor(); }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    private static DateTimeOffset? SafeDate(Func<DateTimeOffset> accessor)
    {
        try { return accessor(); }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }
}