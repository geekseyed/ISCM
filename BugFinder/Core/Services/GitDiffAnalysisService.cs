using System.Text.RegularExpressions;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-10.6: Git Diff Analysis Service
/// Parses git diff output to extract detailed line-by-line changes.
///
/// H-05.1 migration (KBF-10-001): every git invocation goes through the
/// structured GitCommandService layer — ProcessStartInfo.ArgumentList
/// quoting, read-only verb whitelist, global option guard, and
/// GitCommandEvidence provenance (stages 5.1.1-5.1.5). Raw string
/// interpolation ("--full-index -U999999 {from}..{to}") is structurally
/// gone; user-sourced revisions validate as hex SHAs through the H-01.2
/// RevisionId contract BEFORE entering an argument list (5.1.4).
/// Diff-output PARSING is unchanged (H-05.2 owns parser integrity).
/// </summary>
public class GitDiffAnalysisService
{
    private readonly GitCommandService _git = new();
    private readonly string? _repositoryRootPath;

    public GitDiffAnalysisService(string? workingDirectory = null)
    {
        // Try to find repo root if workingDirectory is not provided or not root
        if (string.IsNullOrEmpty(workingDirectory))
        {
            workingDirectory = Directory.GetCurrentDirectory();
        }

        _repositoryRootPath = FindGitRepositoryRoot(workingDirectory);
    }

    /// <summary>
    /// BF-10.6 - Stage 1: Extract diff between two revisions
    /// </summary>
    public GitDiffResult AnalyzeDiff(string fromSha, string toSha)
    {
        if (string.IsNullOrEmpty(_repositoryRootPath))
        {
            throw new InvalidOperationException("Not a Git repository");
        }

        // Stage 5.1.4 — fail-fast on invalid revision input (BEFORE the try:
        // invalid input is meaningless, not absence — it must not be wrapped
        // into "Failed to analyze diff" by the catch below, KBF-10-001)
        var from = GitCommandSafety.ValidateRevision(fromSha, nameof(fromSha));
        var to = GitCommandSafety.ValidateRevision(toSha, nameof(toSha));

        var result = new GitDiffResult
        {
            FromSha = from.Value,
            ToSha = to.Value
        };

        try
        {
            // Structured invocation: -U999999 ensures all context lines for
            // accurate parsing; the range token is built from VALIDATED hex
            // SHAs (5.1.4) — argument list quoting is owned by the OS layer
            var diffOutput = RunGit("diff",
                new[] { "--full-index", "-U999999", $"{from.Value}..{to.Value}" },
                "BF-10.6:full-diff");

            if (string.IsNullOrWhiteSpace(diffOutput))
            {
                return result; // No changes
            }

            result.Files = ParseDiffOutput(diffOutput);
            result.TotalFilesChanged = result.Files.Count;

            // Calculate totals
            foreach (var file in result.Files)
            {
                result.TotalLinesAdded += file.LinesAdded;
                result.TotalLinesDeleted += file.LinesDeleted;
            }

            return result;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to analyze diff: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// BF-10.6 - Stage 2: Parse raw diff output into structured objects
    /// </summary>
    private List<DiffFile> ParseDiffOutput(string diffOutput)
    {
        var files = new List<DiffFile>();
        var lines = diffOutput.Split('\n');

        var currentFile = new DiffFile();
        var currentHunk = new DiffHunk();
        var inHunk = false;
        bool fileInitialized = false;

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];

            // Detect new file section
            if (line.StartsWith("diff --git "))
            {
                if (inHunk && currentHunk.Lines.Any())
                {
                    currentFile.Hunks.Add(currentHunk);
                }

                if (fileInitialized)
                {
                    files.Add(currentFile);
                }

                currentFile = new DiffFile();
                currentHunk = new DiffHunk();
                inHunk = false;
                fileInitialized = true;

                // Extract file paths from diff line
                // Format: diff --git a/path/to/file b/path/to/file
                var parts = line.Split(' ', 4);
                if (parts.Length >= 4)
                {
                    var oldPathPart = parts[2]; // a/path...
                    var newPathPart = parts[3]; // b/path...

                    // Handle spaces in filenames by taking everything after 'a/' and 'b/'
                    if (oldPathPart.StartsWith("a/")) currentFile.OldFilePath = oldPathPart.Substring(2);
                    else currentFile.OldFilePath = oldPathPart;

                    if (newPathPart.StartsWith("b/")) currentFile.NewFilePath = newPathPart.Substring(2);
                    else currentFile.NewFilePath = newPathPart;
                }
            }
            // Detect file mode changes or other metadata
            else if (line.StartsWith("new file"))
            {
                currentFile.ChangeType = FileType.Added;
            }
            else if (line.StartsWith("deleted file"))
            {
                currentFile.ChangeType = FileType.Deleted;
            }
            else if (line.StartsWith("rename from"))
            {
                currentFile.ChangeType = FileType.Renamed;
            }
            // Detect hunk header
            else if (line.StartsWith("@@ "))
            {
                if (inHunk && currentHunk.Lines.Any())
                {
                    currentFile.Hunks.Add(currentHunk);
                }

                currentHunk = ParseHunkHeader(line);
                inHunk = true;
            }
            // Process hunk content
            else if (inHunk)
            {
                var diffLine = ParseDiffLine(line);
                if (diffLine != null)
                {
                    currentHunk.Lines.Add(diffLine);

                    // Update file stats based on line type
                    switch (diffLine.Type)
                    {
                        case LineType.Addition:
                            currentFile.LinesAdded++;
                            break;
                        case LineType.Deletion:
                            currentFile.LinesDeleted++;
                            break;
                    }
                }
            }
        }

        // Add last file if it has content
        if (inHunk && currentHunk.Lines.Any())
        {
            currentFile.Hunks.Add(currentHunk);
        }

        if (fileInitialized && !string.IsNullOrEmpty(currentFile.NewFilePath))
        {
            files.Add(currentFile);
        }

        return files;
    }

    /// <summary>
    /// Parse hunk header like "@@ -1,5 +1,6 @@"
    /// </summary>
    private DiffHunk ParseHunkHeader(string header)
    {
        var hunk = new DiffHunk { Header = header };

        // Regex to parse hunk header: @@ -old_start,old_count +new_start,new_count @@
        var regex = new Regex(@"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@");
        var match = regex.Match(header);

        if (match.Success)
        {
            hunk.OldStartLine = int.Parse(match.Groups[1].Value);
            hunk.OldLineCount = match.Groups[2].Success ? int.Parse(match.Groups[2].Value) : 1;
            hunk.NewStartLine = int.Parse(match.Groups[3].Value);
            hunk.NewLineCount = match.Groups[4].Success ? int.Parse(match.Groups[4].Value) : 1;
        }

        return hunk;
    }

    /// <summary>
    /// Parse individual diff line
    /// </summary>
    private DiffLine? ParseDiffLine(string line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return new DiffLine { Type = LineType.Context, Content = line };
        }

        var firstChar = line[0];
        var content = line.Length > 0 ? line.Substring(1) : string.Empty; // Remove the indicator character

        var diffLine = new DiffLine { Content = content };

        switch (firstChar)
        {
            case ' ':
                diffLine.Type = LineType.Context;
                break;
            case '+':
                diffLine.Type = LineType.Addition;
                break;
            case '-':
                diffLine.Type = LineType.Deletion;
                break;
            case '\\':
                // Ignore "\ No newline at end of file"
                return null;
            default:
                // Ignore other types
                return null;
        }

        return diffLine;
    }

    /// <summary>
    /// Structured git invocation (H-05.1.2/5.1.5) with the legacy verdict
    /// contract preserved: non-zero exit WITH stderr throws, everything
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

    /// <summary>
    /// Helper: Find Git Repository Root
    /// </summary>
    private static string? FindGitRepositoryRoot(string startingDirectory)
    {
        var directory = new DirectoryInfo(startingDirectory);
        while (directory != null)
        {
            var gitDirectory = Path.Combine(directory.FullName, ".git");
            if (Directory.Exists(gitDirectory) || File.Exists(gitDirectory))
            {
                return directory.FullName;
            }
            directory = directory.Parent;
        }
        return null;
    }
}