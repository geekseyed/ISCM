using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-10.2: Current Revision Service — H-05.1 migration to the structured
/// Git command layer (KBF-10-001): ArgumentList quoting, read-only verb
/// whitelist, invocation evidence (5.1.5). Output parsing ('|') stays as
/// H-05.2 scope.
/// </summary>
public class RevisionService
{
    private readonly GitCommandService _git = new();
    private readonly GitIntegrationService _gitService;
    private readonly string? _repositoryRootPath;

    public RevisionService(string? workingDirectory = null)
    {
        _gitService = new GitIntegrationService(workingDirectory);
        _repositoryRootPath = _gitService.GetRepositoryRootPath();
    }

    /// <summary>BF-10.2 - Stage 1-4: Get complete revision snapshot.</summary>
    public RevisionSnapshotResult GetCurrentRevisionSnapshot()
    {
        if (string.IsNullOrEmpty(_repositoryRootPath))
        {
            return new RevisionSnapshotResult
            {
                Success = false,
                ErrorMessage = "Not a Git repository"
            };
        }

        try
        {
            var snapshot = new RevisionSnapshot();

            var basicInfo = _gitService.GetCurrentRevisionInfo();
            if (!basicInfo.IsGitRepository)
            {
                return new RevisionSnapshotResult
                {
                    Success = false,
                    ErrorMessage = "Git repository not found"
                };
            }

            snapshot.CommitSha = basicInfo.CurrentCommitSha ?? string.Empty;
            snapshot.ShortSha = snapshot.CommitSha.Length >= 7
                ? snapshot.CommitSha.Substring(0, 7)
                : snapshot.CommitSha;
            snapshot.BranchName = basicInfo.CurrentBranch ?? string.Empty;
            snapshot.Message = basicInfo.CommitMessage ?? string.Empty;
            snapshot.AuthorName = basicInfo.AuthorName ?? string.Empty;
            snapshot.CommitTimestamp = basicInfo.CommitTimestamp ?? DateTime.MinValue;

            // Enhanced Commit Metadata (parsing is H-05.2 scope)
            var commitDetails = RunGit("show",
                new[] { "-s", "--format=%H|%h|%an|%ae|%ai|%cn|%ce|%ci|%P|%s", "HEAD" },
                "BF-10.2:enhanced-metadata");
            var parts = commitDetails.Split('|');
            if (parts.Length >= 10)
            {
                snapshot.AuthorEmail = parts[3];
                snapshot.CommitterTimestamp = DateTime.TryParse(parts[7], out var ct) ? ct : null;

                if (!string.IsNullOrEmpty(parts[8]))
                {
                    snapshot.ParentShas = parts[8].Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                }
            }

            snapshot.IsDirty = IsWorkingTreeDirty();

            if (snapshot.IsDirty)
            {
                var changedFiles = RunGit("diff",
                    new[] { "--name-only", "HEAD" }, "BF-10.2:dirty-files");
                if (!string.IsNullOrWhiteSpace(changedFiles))
                {
                    snapshot.ChangedFiles = changedFiles
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
                    snapshot.FilesChangedCount = snapshot.ChangedFiles.Count;
                }
            }

            var tags = RunGit("tag",
                new[] { "--points-at", "HEAD" }, "BF-10.2:tags");
            if (!string.IsNullOrWhiteSpace(tags))
            {
                snapshot.TagsOnThisCommit = tags
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
            }

            CalculateDistanceToMain(snapshot);

            return new RevisionSnapshotResult
            {
                Success = true,
                Snapshot = snapshot
            };
        }
        catch (Exception ex)
        {
            return new RevisionSnapshotResult
            {
                Success = false,
                ErrorMessage = ex.Message
            };
        }
    }

    private bool IsWorkingTreeDirty()
    {
        try
        {
            var status = RunGit("status", new[] { "--porcelain" }, "BF-10.2:dirty-state");
            return !string.IsNullOrWhiteSpace(status);
        }
        catch
        {
            return false;
        }
    }

    private void CalculateDistanceToMain(RevisionSnapshot snapshot)
    {
        try
        {
            // NOTE: main/master are INTERNAL fixed candidates — never user input.
            var revParse = RunGit("rev-parse", new[] { "--verify", "main" }, "BF-10.2:main-verify");
            var mainBranch = "main";
            if (string.IsNullOrWhiteSpace(revParse))
            {
                mainBranch = "master";
                revParse = RunGit("rev-parse", new[] { "--verify", "master" }, "BF-10.2:master-verify");
                if (string.IsNullOrWhiteSpace(revParse))
                {
                    return;
                }
            }

            var aheadBehind = RunGit("rev-list",
                new[] { "--left-right", "--count", $"HEAD...{mainBranch}" }, "BF-10.2:ahead-behind");
            if (string.IsNullOrWhiteSpace(aheadBehind) && mainBranch == "main")
            {
                aheadBehind = RunGit("rev-list",
                    new[] { "--left-right", "--count", "HEAD...master" }, "BF-10.2:ahead-behind-master");
            }

            if (!string.IsNullOrWhiteSpace(aheadBehind))
            {
                var parts = aheadBehind.Split('\t');
                if (parts.Length == 2)
                {
                    if (int.TryParse(parts[0], out var ahead))
                    {
                        snapshot.CommitsAheadOfMain = ahead;
                    }
                    if (int.TryParse(parts[1], out var behind))
                    {
                        snapshot.CommitsBehindMain = behind;
                    }
                }
            }
        }
        catch
        {
            // Ignore errors in distance calculation
        }
    }

    /// <summary>Structured invocation (5.1.2/5.1.5) with the legacy verdict contract.</summary>
    private string RunGit(string verb, IReadOnlyList<string> arguments, string purpose)
    {
        var evidence = _git.Run(new GitCommandRequest
        {
            Verb = verb,
            Arguments = arguments,
            WorkingDirectory = _repositoryRootPath ?? Directory.GetCurrentDirectory(),
            Purpose = purpose
        });

        GitCommandService.ThrowIfFailed(evidence);
        return evidence.StdOut.Trim();
    }
}