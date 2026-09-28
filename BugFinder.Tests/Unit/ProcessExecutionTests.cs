using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class ProcessExecutionTests
{
    private readonly ProcessExecutionService _service = new();

    // ---------- Stage 3.1.1/3.1.3 — structured arguments ----------

    [Fact]
    public void BuildArguments_StructuredList_ContainsProjectAndLogger()
    {
        var args = _service.BuildArguments(@"tests\X.csproj", @"TestResults\run.trx");

        args.Should().Contain("test");
        args.Should().Contain(@"tests\X.csproj");
        args.Should().Contain("--logger");
        args.Should().Contain(arg => arg.Contains("trx;LogFileName="));
        args.Should().Contain("--no-restore");
    }

    // KBF-01-004 — no hard-coded default target (fail-fast ArgumentException)
    [Fact]
    public void BuildArguments_EmptyProjectPath_Throws_NoDefaultInvented()
    {
        Action act = () => _service.BuildArguments("  ", @"TestResults\run.trx");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*no default target*");
    }

    [Fact]
    public void BuildArguments_EmptyArtifactPath_Throws()
    {
        Action act = () => _service.BuildArguments("x.csproj", " ");
        act.Should().Throw<ArgumentException>();
    }

    // ---------- Stage 3.1.2 — working directory validation ----------

    [Fact]
    public void ValidateWorkingDirectory_NonExistent_Throws()
    {
        Action act = () => _service.ValidateWorkingDirectory(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "no-such-dir-h01z9"));
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateWorkingDirectory_Empty_Throws()
    {
        Action act = () => _service.ValidateWorkingDirectory(" ");
        act.Should().Throw<ArgumentException>();
    }

    // ---------- Stage 3.1.4-3.1.6 — REAL process evidence (raw runner) ----------

    [Fact]
    public async Task ExecuteRaw_SuccessExitCode_Captured()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var result = await _service.ExecuteRawAsync(
            input, new[] { "/c", "exit", "0" });

        result.Kind.Should().Be(ServiceResultKind.Success);
        var evidence = result.Value!;

        evidence.ExitCode.Should().Be(0);
        evidence.ProcessId.Should().NotBeNull();                 // 3.1.4
        evidence.StartUtc.Should().NotBeNull();                  // 3.1.5
        evidence.EndUtc.Should().NotBeNull();                    // 3.1.6
        evidence.EndUtc!.Value.Should().BeOnOrAfter(evidence.StartUtc!.Value);
        evidence.Duration.Should().NotBeNull();
        evidence.Executable.Should().Be("cmd.exe");
        evidence.TerminatedByCancellation.Should().BeFalse();
    }

    // KBF-01-001 — THE fabrication fix: a REAL non-zero exit code survives
    [Fact]
    public async Task ExecuteRaw_RealNonZeroExitCode_PreservedNotFabricated()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var result = await _service.ExecuteRawAsync(
            input, new[] { "/c", "exit", "42" });

        result.Kind.Should().Be(ServiceResultKind.Success);

        // THE assertion: 42 survives (pre-H-03.1 it was overwritten by 0)
        result.Value!.ExitCode.Should().Be(42);
    }

    // KBF-01-007 — timestamps are OBSERVED (within sane bounds), not fabricated
    [Fact]
    public async Task ExecuteRaw_Timestamps_ObservedAndCoherent()
    {
        var before = DateTimeOffset.UtcNow.AddSeconds(-5);
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var result = await _service.ExecuteRawAsync(input, new[] { "/c", "exit", "0" });

        var evidence = result.Value!;
        evidence.StartUtc!.Value.Should().BeOnOrAfter(before);
        evidence.EndUtc!.Value.Should().BeOnOrAfter(evidence.StartUtc.Value);
        evidence.Duration!.Value.Should().BeLessOrEqualTo(TimeSpan.FromSeconds(30));
    }

    // stdout capture works through the raw runner (H-03.7 seed)
    [Fact]
    public async Task ExecuteRaw_StdoutEcho_Runs()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var result = await _service.ExecuteRawAsync(
            input, new[] { "/c", "echo", "hello-bugfinder" });

        result.Kind.Should().Be(ServiceResultKind.Success);
        result.Value!.ExitCode.Should().Be(0);
    }

    // ================================================================
    // H-03.3 — cancellation & process lifetime
    // ================================================================

    // Stage 3.3.1 — cancel BEFORE launch: nothing starts, Unavailable
    [Fact]
    public async Task Cancel_BeforeLaunch_Unavailable_NoProcessStarted()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        using var cts = new CancellationTokenSource();
        cts.Cancel();   // cancel BEFORE launch

        var result = await _service.ExecuteRawAsync(
            input, new[] { "/c", "exit", "0" }, cts.Token);

        result.Kind.Should().Be(ServiceResultKind.Unavailable);
        result.HasValue.Should().BeFalse();
        result.Reasons.Should().Contain(r => r.Contains("not started"));
    }

    // Stages 3.3.2-3.3.4 — cancel MID-RUN: tree killed, evidence captured,
    // returned as Partial (payload + gap reason)
    [Fact]
    public async Task Cancel_MidRun_PartialEvidenceWithTerminationMarker()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        using var cts = new CancellationTokenSource();
        var launchTask = _service.ExecuteRawAsync(
            input, new[] { "/c", "ping", "127.0.0.1", "-n", "30" }, cts.Token);

        await Task.Delay(500);   // let the process actually start
        cts.Cancel();

        var result = await launchTask;

        result.Kind.Should().Be(ServiceResultKind.Partial);
        result.HasValue.Should().BeTrue();

        var evidence = result.Value!;
        evidence.TerminatedByCancellation.Should().BeTrue();     // 3.3.4 marker
        evidence.ProcessId.Should().NotBeNull();
        evidence.StartUtc.Should().NotBeNull();
        evidence.EndUtc.Should().NotBeNull();                    // OS-recorded kill time
        evidence.EndUtc!.Value.Should().BeOnOrAfter(evidence.StartUtc!.Value);
        result.Reasons.Should().Contain(r => r.Contains("cancelled before completion"));
    }

    // Stage 3.3.5 — no orphaned hosts: the captured PID is DEAD after return
    [Fact]
    public async Task Cancel_MidRun_NoOrphanedProcess()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        using var cts = new CancellationTokenSource();
        var launchTask = _service.ExecuteRawAsync(
            input, new[] { "/c", "ping", "127.0.0.1", "-n", "30" }, cts.Token);

        await Task.Delay(500);
        cts.Cancel();

        var result = await launchTask;
        var pid = result.Value!.ProcessId!.Value;

        // H-03.3.5 — poll briefly: the process must be gone (or HasExited)
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
                gone = true;   // no such process = terminated
            }
            if (!gone) await Task.Delay(100);
        }

        gone.Should().BeTrue(
            "cancelled child processes must be terminated, not orphaned (H-03.3.5)");
    }

    // Completed runs are NOT marked as terminated-by-cancellation
    [Fact]
    public async Task CompletedRun_NotMarkedAsTerminated()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        var result = await _service.ExecuteRawAsync(input, new[] { "/c", "exit", "0" });

        result.Value!.TerminatedByCancellation.Should().BeFalse();
    }

    // Contract violations fail fast (H-01.8 boundary: programmer error)
    [Fact]
    public async Task Execute_InvalidWorkingDirectory_Throws()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = @"Z:\definitely-missing-dir",
            Executable = "cmd.exe"
        };

        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.ExecuteRawAsync(input, new[] { "/c", "exit", "0" }));
    }

    [Fact]
    public async Task Execute_NullInput_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _service.ExecuteRawAsync(null!, new[] { "/c", "exit", "0" }));
    }

    [Fact]
    public async Task Execute_NullArguments_Throws()
    {
        var input = new ProcessLaunchInput
        {
            WorkingDirectory = System.IO.Path.GetTempPath(),
            Executable = "cmd.exe"
        };

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _service.ExecuteRawAsync(input, null!));
    }
}