using System.Diagnostics;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-03.1: Process Execution Service — launches processes and captures
/// launch/lifetime evidence WITHOUT interpreting them.
///
/// FIXES AT THE SOURCE (vs the legacy TestExecutionService):
///   KBF-01-004  the dotnet test target is a MANDATORY input — the
///               ISCM.Tests/ISCM.Tests.csproj default is gone.
///   KBF-01-001  the REAL exit code is returned in the evidence; no
///               "ExitCode = 0 for ingestion" fabrication, no exception
///               swallowing - classification belongs to H-03.2.
///   KBF-01-007  timestamps come from the OS process object (StartTime/
///               ExitTime), not DateTime.UtcNow.
///   KBF-10-001  arguments via ProcessStartInfo.ArgumentList — no raw
///               interpolation, no manual quoting.
///   KBF-01-002  cancellation kills the child process and waits
///               (child-process lifetime is owned here; H-03.3 deepens).
///
/// TWO LAUNCH SHAPES:
///   ExecuteAsync     - dotnet-test shaped (arguments built here)
///   ExecuteRawAsync  - caller supplies the FULL argument list
///                      (generic process runner; used by tests, probes
///                      and future engine stages)
///
/// INPUT VALIDATION = FAIL-FAST ArgumentException (programmer error,
/// H-01.8 boundary); RUNTIME problems (process won't start, cancelled,
/// unexpected engine exception) = ServiceResult Unavailable/DiagnosticError.
///
/// Interpretation (test-failed vs build-failed vs discovery-failed)
/// deliberately NOT here — that is H-03.2/H-03.9.
/// </summary>
public class ProcessExecutionService
{
    /// <summary>Validate + build the structured dotnet-test arguments (3.1.1/3.1.3).</summary>
    public IReadOnlyList<string> BuildArguments(string testProjectPath, string resultArtifactPath)
    {
        if (string.IsNullOrWhiteSpace(testProjectPath))
            throw new ArgumentException(
                "Test project path is required - no default target is invented " +
                "(audit KBF-01-004).", nameof(testProjectPath));
        if (string.IsNullOrWhiteSpace(resultArtifactPath))
            throw new ArgumentException("Result artifact path is required.", nameof(resultArtifactPath));

        // structured list: quoting/escaping owned by the OS layer
        return new List<string>
        {
            "test",
            testProjectPath,
            "--logger", $"trx;LogFileName={resultArtifactPath}",
            "--verbosity", "normal",
            "--no-restore"
        };
    }

    /// <summary>Validate working directory (3.1.2) — must exist.</summary>
    public string ValidateWorkingDirectory(string workingDirectory)
    {
        if (string.IsNullOrWhiteSpace(workingDirectory))
            throw new ArgumentException("Working directory is required.", nameof(workingDirectory));

        var full = Path.GetFullPath(workingDirectory);
        if (!Directory.Exists(full))
            throw new ArgumentException(
                $"Working directory does not exist: '{full}'.", nameof(workingDirectory));
        return full;
    }

    /// <summary>dotnet-test shaped launch (arguments built by BuildArguments).</summary>
    public Task<ServiceResult<ProcessExecutionEvidence>> ExecuteAsync(
        ProcessLaunchInput input, CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        var arguments = BuildArguments(input.TestProjectPath, input.ResultArtifactPath ?? string.Empty);
        return ExecuteRawAsync(input, arguments, cancellationToken);
    }

    /// <summary>
    /// Generic raw launch: caller owns the FULL argument list (the Core
    /// still owns working-dir validation, child-process lifetime, and
    /// evidence capture). This is the shape tests/probes/H-03.2 use.
    /// </summary>
    public async Task<ServiceResult<ProcessExecutionEvidence>> ExecuteRawAsync(
        ProcessLaunchInput input,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (input is null) throw new ArgumentNullException(nameof(input));
            if (arguments is null) throw new ArgumentNullException(nameof(arguments));

            var workingDirectory = ValidateWorkingDirectory(input.WorkingDirectory);

            var startInfo = new ProcessStartInfo
            {
                FileName = input.Executable,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var argument in arguments)
                startInfo.ArgumentList.Add(argument);

            var outputBuilder = new System.Text.StringBuilder();
            var errorBuilder = new System.Text.StringBuilder();

            using var process = new Process { StartInfo = startInfo };
            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) outputBuilder.AppendLine(e.Data);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data)) errorBuilder.AppendLine(e.Data);
            };

            if (!process.Start())
                return ServiceResult<ProcessExecutionEvidence>.Unavailable(
                    "process failed to start", nameof(ProcessExecutionService));

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // H-03.1.4/3.1.5 — id + observed start (OS-provided)
            int? processId = SafeInt(() => process.Id);
            DateTimeOffset? startUtc = SafeDate(() =>
                new DateTimeOffset(process.StartTime.ToUniversalTime()));

            try
            {
                await process.WaitForExitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // H-03.3 seed — terminate the child and wait (no orphans)
                try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
                try { await process.WaitForExitAsync(CancellationToken.None); } catch { }

                return ServiceResult<ProcessExecutionEvidence>.Unavailable(
                    "execution cancelled before completion",
                    nameof(ProcessExecutionService));
            }

            // H-03.1.6/3.2.1 — observed end + REAL exit code
            DateTimeOffset? endUtc = SafeDate(() =>
                new DateTimeOffset(process.ExitTime.ToUniversalTime()));

            var evidence = new ProcessExecutionEvidence
            {
                ProcessId = processId,
                StartUtc = startUtc,
                EndUtc = endUtc,
                ExitCode = SafeExitCode(process),
                Executable = input.Executable,
                Arguments = arguments.ToList(),
                WorkingDirectory = workingDirectory,
                TestProjectPath = input.TestProjectPath,
                ResultArtifactPath = input.ResultArtifactPath ?? string.Empty
            };

            // stdout/stderr stay in the result as raw provenance (H-03.7 owns
            // structured segmentation) - callers read them from the artifact.
            return ServiceResult<ProcessExecutionEvidence>.Success(evidence);
        }
        catch (Exception ex) when (ex is not ArgumentNullException and not ArgumentException)
        {
            return ServiceResult<ProcessExecutionEvidence>.DiagnosticError(ex,
                nameof(ProcessExecutionService));
        }
    }

    /// <summary>Real exit code; null only when the OS refuses to tell.</summary>
    private static int? SafeExitCode(Process process)
    {
        try { return process.ExitCode; }
        catch (InvalidOperationException) { return null; }
    }

    private static T? Safe<T>(Func<T> accessor) where T : class
    {
        try { return accessor(); }
        catch (InvalidOperationException) { return null; }   // process gone / not started
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    /// <summary>
    /// Nullable-struct variant (DateTimeOffset is a value type - the
    /// class-constrained Safe<T> cannot resolve it, and silently falling
    /// back to Safe(Func<int>) produced CS0029).
    /// </summary>
    private static DateTimeOffset? SafeDate(Func<DateTimeOffset> accessor)
    {
        try { return accessor(); }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }
    private static int? SafeInt(Func<int> accessor)
    {
        try { return accessor(); }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }
}