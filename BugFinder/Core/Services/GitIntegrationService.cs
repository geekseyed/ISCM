using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-10.1: Git Integration Service — H-05.1 migration to the structured
/// Git command layer (KBF-10-001 / stages 5.1.1-5.1.5):
///   every invocation goes through GitCommandService (ArgumentList,
///   read-only verb whitelist, option guard) — raw string interpolation
///   is structurally gone; user-sourced revisions validate as hex SHAs
///   through the H-01.2 RevisionId contract BEFORE entering an argument
///   list (5.1.4); every invocation records GitCommandEvidence (5.1.5).
/// Parsing of git OUTPUT (the '|' separator fragility, KBF-10-002)
/// belongs to H-05.2 and is deliberately untouched here.
/// </summary>
public class GitIntegrationService
{
    private readonly GitCommandService _git = new();
    private readonly string? _repositoryRootPath;

    public GitIntegrationService(string? workingDirectory = null)
    {
        _repositoryRootPath = FindRepositoryRoot(workingDirectory ?? Directory.GetCurrentDirectory());
    }

    /// <summary>BF-10.1 - Stage 1: Repository Detection.</summary>
    public bool IsGitRepository() => !string.IsNullOrEmpty(_repositoryRootPath);

    /// <summary>BF-10.1 - Stage 1 &amp; 2: Get Repository Root Path.</summary>
    public string? GetRepositoryRootPath() => _repositoryRootPath;

    /// <summary>BF-10.2 - Stage 1-4: Get Current Revision Info.</summary>
    public GitRepositoryInfo GetCurrentRevisionInfo()
    {
        if (string.IsNullOrEmpty(_repositoryRootPath))
        {
            return new GitRepositoryInfo { IsGitRepository = false };
        }

        var info = new GitRepositoryInfo
        {
            RepositoryRootPath = _repositoryRootPath,
            IsGitRepository = true
        };

        try
        {
            // Current Branch
            info.CurrentBranch = RunGit("rev-parse",
                new[] { "--abbrev-ref", "HEAD" }, "BF-10.2:current-branch");

            // Current Commit SHA
            info.CurrentCommitSha = RunGit("rev-parse",
                new[] { "HEAD" }, "BF-10.2:current-sha");

            // Commit Metadata (parsing itself is H-05.2 scope)
            var commitDetails = RunGit("show",
                new[] { "-s", "--format=%H|%an|%ae|%ai|%s", "HEAD" }, "BF-10.2:commit-metadata");

            var parts = commitDetails.Split('|');
            if (parts.Length >= 5)
            {
                info.AuthorName = parts[1];
                if (DateTime.TryParse(parts[3], out var timestamp))
                {
                    info.CommitTimestamp = timestamp;
                }
                info.CommitMessage = parts[4];
            }
        }
        catch
        {
            // Gracefully handle git command failures (diagnostics: H-05.2)
        }

        return info;
    }

    /// <summary>BF-10.5 - Stage 2: Enumerate commits between two revisions.</summary>
    public List<CommitInfo> GetCommitsBetween(string fromSha, string toSha)
    {
        var commits = new List<CommitInfo>();

        if (string.IsNullOrEmpty(_repositoryRootPath))
        {
            return commits;
        }

        // Stage 5.1.4 — fail-fast on invalid revision input (OUTSIDE the try:
        // invalid input is not absence; it must not be swallowed, KBF-10-001)
        var from = GitCommandSafety.ValidateRevision(fromSha, nameof(fromSha));
        var to = GitCommandSafety.ValidateRevision(toSha, nameof(toSha));

        try
        {
            var logOutput = RunGit("log",
                new[] { "--pretty=format:%H|%an|%ai|%s", $"{from.Value}..{to.Value}" },
                "BF-10.5:commit-log");

            if (string.IsNullOrWhiteSpace(logOutput))
            {
                return commits;
            }

            var lines = logOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Split('|');
                if (parts.Length >= 4)
                {
                    var sha = parts[0];
                    var commit = new CommitInfo
                    {
                        Sha = sha,
                        ShortSha = sha.Substring(0, Math.Min(7, sha.Length)),
                        AuthorName = parts[1],
                        Message = parts[3]
                    };

                    if (DateTime.TryParse(parts[2], out var timestamp))
                    {
                        commit.Timestamp = timestamp;
                    }

                    // Changed files — the SHA came from git output, but the
                    // guard is applied anyway (defense in depth, 5.1.4)
                    if (RevisionId.TryParse(sha, out var validatedSha))
                    {
                        var filesOutput = RunGit("diff-tree",
                            new[] { "--no-commit-id", "--name-only", "-r", validatedSha.Value },
                            "BF-10.5:commit-files");
                        if (!string.IsNullOrWhiteSpace(filesOutput))
                        {
                            commit.ChangedFiles = filesOutput
                                .Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
                        }
                    }

                    commits.Add(commit);
                }
            }
        }
        catch
        {
            // Handle errors gracefully (diagnostics: H-05.2)
        }

        return commits;
    }

    /// <summary>BF-10.6 - Stage 1: Get diff between two commits.</summary>
    public string GetDiff(string fromSha, string toSha, string? filePath = null)
    {
        if (string.IsNullOrEmpty(_repositoryRootPath))
        {
            return string.Empty;
        }

        var from = GitCommandSafety.ValidateRevision(fromSha, nameof(fromSha));
        var to = GitCommandSafety.ValidateRevision(toSha, nameof(toSha));

        try
        {
            var args = new List<string> { $"{from.Value}..{to.Value}" };
            if (!string.IsNullOrEmpty(filePath))
            {
                args.Add("--");   // pathspec separator — the path can never be parsed as an option
                args.Add(GitCommandSafety.ValidatePath(filePath, nameof(filePath)));
            }

            return RunGit("diff", args, "BF-10.6:diff");
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>Helper: Find repository root by traversing up the directory tree.</summary>
    private string? FindRepositoryRoot(string startPath)
    {
        var currentDir = new DirectoryInfo(startPath);

        while (currentDir != null)
        {
            if (Directory.Exists(Path.Combine(currentDir.FullName, ".git")))
            {
                return currentDir.FullName;
            }
            currentDir = currentDir.Parent;
        }

        return null;
    }

    /// <summary>
    /// Structured invocation (5.1.2/5.1.5) preserving the legacy verdict:
    /// non-zero exit WITH stderr throws (previous contract), everything
    /// else returns trimmed stdout.
    /// </summary>
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