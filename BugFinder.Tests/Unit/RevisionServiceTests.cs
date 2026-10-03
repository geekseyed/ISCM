using System.Diagnostics;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class RevisionServiceTests
{
    [Fact]
    public void GetCurrentRevisionSnapshot_WhenInRepo_ReturnsSuccess()
    {
        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Success.Should().BeTrue();
        result.Snapshot.Should().NotBeNull();
        result.ErrorMessage.Should().BeNullOrEmpty();
    }

    [Fact]
    public void GetCurrentRevisionSnapshot_ContainsValidSha()
    {
        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Snapshot!.CommitSha.Should().NotBeNullOrEmpty();
        result.Snapshot.ShortSha.Length.Should().Be(7);
    }

    // REPAIRED (was: BranchName.Should().Contain("phase10") — a hard-coded
    // phase name from phase10; environment-coupled and wrong on every other
    // branch). The expectation is now DERIVED from the actual repository:
    // the snapshot's branch must equal the real git answer.
    [Fact]
    public void GetCurrentRevisionSnapshot_ContainsBranchName_MatchesActualGitBranch()
    {
        var expected = CaptureGit("rev-parse", "--abbrev-ref", "HEAD");

        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Snapshot!.BranchName.Should().NotBeNullOrEmpty();
        result.Snapshot.BranchName.Should().Be(expected);
    }

    // REPAIRED (was: assumed a dirty working tree — environment-coupled).
    // The expectation is derived from the actual `git status --porcelain`
    // state, and the changed-file count must be internally consistent.
    [Fact]
    public void GetCurrentRevisionSnapshot_DetectsDirtyState_MatchesActualGitStatus()
    {
        var porcelain = CaptureGit("status", "--porcelain");
        var expectedDirty = porcelain.Trim().Length > 0;

        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Snapshot!.IsDirty.Should().Be(expectedDirty);
        if (expectedDirty)
        {
            result.Snapshot.FilesChangedCount.Should().BeGreaterThan(0);
        }
        else
        {
            result.Snapshot.FilesChangedCount.Should().Be(0);
        }
    }

    [Fact]
    public void GetCurrentRevisionSnapshot_HasParentCommit()
    {
        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Snapshot!.ParentShas.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetCurrentRevisionSnapshot_CalculatesDistanceToMain()
    {
        var result = new RevisionService().GetCurrentRevisionSnapshot();

        result.Snapshot!.CommitsAheadOfMain.Should().BeGreaterOrEqualTo(0);
    }

    /// <summary>Real git answer via ArgumentList (KBF-10-001 pattern, even in tests).</summary>
    private static string CaptureGit(params string[] args)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "git",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in args)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        return output;
    }
}