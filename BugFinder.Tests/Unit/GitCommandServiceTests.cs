using System.Diagnostics;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class GitCommandServiceTests : IDisposable
{
    private readonly GitCommandService _service = new();
    private readonly string _repo;

    public GitCommandServiceTests()
    {
        _repo = Path.Combine(Path.GetTempPath(), $"gcs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_repo);
        Git("init");
        Git("config", "user.email", "bugfinder-test@example.com");
        Git("config", "user.name", "BugFinder Tests");
        File.WriteAllText(Path.Combine(_repo, "README.md"), "seed\n");
        Git("add", ".");
        Git("commit", "-m", "initial");
    }

    public void Dispose()
    {
        try { Directory.Delete(_repo, recursive: true); } catch { }
    }

    private void Git(params string[] args) => _ = GitOut(args);

    private string GitOut(params string[] args)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "git",
            WorkingDirectory = _repo,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in args)
        {
            startInfo.ArgumentList.Add(argument);   // KBF-10-001 pattern, even in test setup
        }

        using var process = Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"setup git failed: {string.Join(' ', args)} — {stderr.Trim()}");
        return stdout.Trim();
    }

    private GitCommandRequest InRepo(string verb, IEnumerable<string> args, string purpose = "test") =>
        new() { Verb = verb, Arguments = args.ToList(), WorkingDirectory = _repo, Purpose = purpose };

    // 5.1.1/5.1.2 — structured invocation in a REAL repo succeeds
    [Fact]
    public void Run_RevParseHead_Succeeds()
    {
        var evidence = _service.Run(InRepo("rev-parse", new[] { "HEAD" }));

        evidence.Succeeded.Should().BeTrue();
        evidence.ExitCode.Should().Be(0);
        evidence.StdOut.Trim().Should().MatchRegex("^[0-9a-f]{40}$");
        evidence.TerminatedByCancellation.Should().BeFalse();
    }

    // 5.1.5 — provenance fields: audit copy, purpose, process truth, OS timestamps
    [Fact]
    public void Run_RecordsEvidence_ProvenanceFields()
    {
        var evidence = _service.Run(InRepo("rev-parse", new[] { "--abbrev-ref", "HEAD" }, "test:branch"));

        evidence.Arguments.First().Should().Be("rev-parse");
        evidence.Arguments.Should().Contain("--abbrev-ref").And.Contain("HEAD");
        evidence.Purpose.Should().Be("test:branch");
        evidence.WorkingDirectory.Should().Be(Path.GetFullPath(_repo));
        evidence.ProcessId.Should().BeGreaterThan(0);
        evidence.StartUtc.Should().NotBeNull();
        evidence.EndUtc.Should().NotBeNull();
        evidence.EndUtc!.Value.Should().BeOnOrAfter(evidence.StartUtc!.Value);
    }

    // failed command = evidence (NOT an exception) — real exit code + stderr.
    // GIT BEHAVIOR LESSON (pinned, twice-verified against real git):
    // rev-parse NEVER consults the object database for a full 40-hex string —
    // bare `rev-parse <sha>` ECHOES it (exit 0), and even `--verify <sha>`
    // only checks sha1-convertibility, NOT existence. Real existence checking
    // requires the `^{object}` suffix (or `git cat-file -e`). The service was
    // correct both times; the expectation had to be derived from REAL git
    // behavior, not assumptions.
    [Fact]
    public void Run_NonExistentRevision_FailedEvidenceWithoutThrow()
    {
        var evidence = _service.Run(InRepo("rev-parse",
            new[] { "--verify", "0123456789abcdef0123456789abcdef01234567^{object}" }));

        evidence.Succeeded.Should().BeFalse();
        evidence.ExitCode.Should().NotBe(0);
        evidence.StdErr.Should().NotBeNullOrWhiteSpace();
    }

    // 5.1.1 — mutating verbs are structurally unreachable
    [Fact]
    public void Run_VerbOutsideWhitelist_Throws()
    {
        Action act = () => _service.Run(InRepo("push", Array.Empty<string>()));

        act.Should().Throw<InvalidOperationException>()
            .And.Message.Should().Contain("whitelist");
    }

    // 5.1.3 — working directory must exist
    [Fact]
    public void Run_MissingWorkingDirectory_Throws()
    {
        var request = new GitCommandRequest
        {
            Verb = "rev-parse",
            Arguments = new[] { "HEAD" },
            WorkingDirectory = Path.Combine(_repo, "does-not-exist"),
            Purpose = "test"
        };

        Action act = () => _service.Run(request);
        act.Should().Throw<ArgumentException>();
    }

    // 5.1.5 — cancellation BEFORE launch: evidence without a process
    [Fact]
    public void Run_CancelledBeforeStart_TerminatedEvidence()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var evidence = _service.Run(InRepo("rev-parse", new[] { "HEAD" }), cts.Token);

        evidence.TerminatedByCancellation.Should().BeTrue();
        evidence.ProcessId.Should().BeNull();
        evidence.Succeeded.Should().BeFalse();
    }

    // end-to-end — REAL diff between two REAL commits in the temp repo
    [Fact]
    public void Run_DiffBetweenTwoCommits_CapturesRealDiffOutput()
    {
        var firstSha = GitOut("rev-parse", "HEAD");
        File.WriteAllText(Path.Combine(_repo, "a.txt"), "one\n");
        Git("add", ".");
        Git("commit", "-m", "second");
        var secondSha = GitOut("rev-parse", "HEAD");

        var evidence = _service.Run(InRepo("diff",
            new[] { $"{firstSha}..{secondSha}" }, "test:diff"));

        evidence.Succeeded.Should().BeTrue();
        evidence.StdOut.Should().Contain("diff --git");
        evidence.StdOut.Should().Contain("b/a.txt");
        evidence.StdOut.Should().Contain("+one");
    }

    // 5.1.4 — revision validation: only hex SHAs pass (KBF-10-001)
    [Theory]
    [InlineData("HEAD")]
    [InlineData("HEAD; rm -rf /")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("zzzz")]      // non-hex
    [InlineData("012345")]    // 6 hex chars — below the 7-char minimum
    public void ValidateRevision_Malformed_Throws(string bad)
    {
        FluentActions.Invoking(() => GitCommandSafety.ValidateRevision(bad, "v"))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateRevision_AcceptsFullSha()
    {
        var revision = GitCommandSafety.ValidateRevision(
            "0123456789abcdef0123456789abcdef01234567", "v");

        revision.Value.Should().Be("0123456789abcdef0123456789abcdef01234567");
    }

    // path guard — dash-start / escape / rooted are rejected
    [Theory]
    [InlineData("-rf")]
    [InlineData("../up")]
    [InlineData("/abs")]
    [InlineData("C:/abs")]
    public void ValidatePath_Throws(string bad)
    {
        FluentActions.Invoking(() => GitCommandSafety.ValidatePath(bad, "p"))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidatePath_AcceptsRelative()
    {
        var path = GitCommandSafety.ValidatePath("  src/File.cs  ", "p");
        path.Should().Be("src/File.cs");
    }

    // layer 4 — forbidden options are rejected globally
    [Fact]
    public void ValidateArguments_ForbiddenOptionToken_Throws()
    {
        FluentActions.Invoking(() =>
                GitCommandSafety.ValidateArguments(new[] { "--upload-pack", "x" }))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ValidateArguments_ControlCharacter_Throws()
    {
        FluentActions.Invoking(() =>
                GitCommandSafety.ValidateArguments(new[] { "\u0000x" }))
            .Should().Throw<ArgumentException>();
    }

    // legacy verdict contract preserved on top of evidence
    [Fact]
    public void ThrowIfFailed_WithStdErr_Throws()
    {
        var evidence = new GitCommandEvidence { ExitCode = 128, StdErr = "fatal: bad revision" };
        FluentActions.Invoking(() => GitCommandService.ThrowIfFailed(evidence))
            .Should().Throw<InvalidOperationException>()
            .And.Message.Should().Contain("fatal: bad revision");
    }

    [Fact]
    public void ThrowIfFailed_FailWithoutStdErr_DoesNotThrow()
    {
        var evidence = new GitCommandEvidence { ExitCode = 1, StdErr = string.Empty };
        FluentActions.Invoking(() => GitCommandService.ThrowIfFailed(evidence))
            .Should().NotThrow();
    }

    [Fact]
    public void ThrowIfFailed_Success_DoesNotThrow()
    {
        var evidence = new GitCommandEvidence { ExitCode = 0, StdOut = "ok" };
        FluentActions.Invoking(() => GitCommandService.ThrowIfFailed(evidence))
            .Should().NotThrow();
    }
}