using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-05.1: Git Command Safety Models
/// (audit KBF-10-001 P0: git arguments were passed as a single
/// interpolated command-line string — paths/subjects containing spaces
/// or special characters are fragile; quoting is inconsistent.
///  + KBF-10-002: commit metadata was split on '|' — a commit subject
/// containing '|' can corrupt parsing.)
///
/// Stage 5.1.1  GitCommandRequest — a STRUCTURED command: whitelisted
///              read-only verb + argument list + validated working
///              directory + a call-site Purpose tag (provenance).
/// Stage 5.1.2  no raw interpolation anywhere: the argument list IS the
///              command; quoting/escaping is owned by the OS layer
///              (ProcessStartInfo.ArgumentList — the H-03.1 pattern).
/// Stage 5.1.3  working directory must be an existing directory.
/// Stage 5.1.4  user-sourced revisions MUST validate as hex SHAs through
///              the H-01.2 RevisionId contract (GitCommandSafety.
///              ValidateRevision) BEFORE entering any argument list.
/// Stage 5.1.5  GitCommandEvidence — the audit copy of every invocation:
///              exact arguments, purpose, process id, OS-recorded
///              timestamps, REAL exit code, stdout/stderr.
///
/// NOTE: parsing of git OUTPUT (the '|' fragility, KBF-10-002) belongs
/// to H-05.2 and is deliberately untouched in H-05.1.
/// </summary>
public sealed class GitCommandRequest
{
    /// <summary>Git subcommand — must be in the read-only whitelist (5.1.1).</summary>
    public string Verb { get; init; } = string.Empty;

    /// <summary>Structured arguments (each token separate — never one joined string).</summary>
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();

    /// <summary>Repository root / working directory (must exist — 5.1.3).</summary>
    public string WorkingDirectory { get; init; } = string.Empty;

    /// <summary>Call-site tag for evidence provenance (5.1.5).</summary>
    public string Purpose { get; init; } = string.Empty;
}

/// <summary>
/// Captured evidence of one git invocation (5.1.5). Succeeded is derived
/// from the REAL exit code — never fabricated (H-03.2 continuity).
/// Timestamps are OS-recorded (observed), never DateTime.UtcNow (X-003).
/// </summary>
public sealed class GitCommandEvidence
{
    public string Verb { get; init; } = string.Empty;
    public string Purpose { get; init; } = string.Empty;

    /// <summary>The FULL executed argument list including the verb (audit copy).</summary>
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();

    public string WorkingDirectory { get; init; } = string.Empty;

    public int? ProcessId { get; init; }
    public DateTimeOffset? StartUtc { get; init; }
    public DateTimeOffset? EndUtc { get; init; }

    /// <summary>REAL process exit code — null only when the OS refuses to tell.</summary>
    public int? ExitCode { get; init; }

    public bool TerminatedByCancellation { get; init; }

    public string StdOut { get; init; } = string.Empty;
    public string StdErr { get; init; } = string.Empty;

    /// <summary>True ONLY for a completed run with exit code 0 — Unknown/missing exit code is not success.</summary>
    public bool Succeeded => ExitCode == 0 && !TerminatedByCancellation;
}

/// <summary>
/// H-05.1 input validation (defense in depth):
///   layer 1 — verb whitelist (read-only verbs only; mutating
///             capabilities are structurally unreachable from Core);
///   layer 2 — revisions as hex SHAs via the H-01.2 RevisionId contract;
///   layer 3 — path arguments: relative, no dash, no "..", no control
///             characters (always used AFTER a "--" pathspec separator);
///   layer 4 — global option deny-list (-c / --exec / --upload-pack /
///             --receive-pack can execute or reconfigure git).
/// </summary>
public static class GitCommandSafety
{
    private static readonly HashSet<string> AllowedVerbSet = new(StringComparer.Ordinal)
    {
        // read-only verbs actually used by the regression pipeline (H-05.x).
        // write-capable verbs (add/commit/push/checkout/reset/...) are
        // ABSENT — Strict Core Boundary, H-10.2.4 continuity.
        "rev-parse", "show", "log", "diff", "diff-tree", "status", "rev-list", "tag"
    };

    private static readonly string[] ForbiddenOptionTokens =
    {
        "-c", "--exec", "--upload-pack", "--receive-pack",
        "-o", "--config-env", "--git-dir", "--work-tree", "--namespace", "--super-prefix"
    };

    public static bool IsVerbAllowed(string verb) =>
        AllowedVerbSet.Contains(verb);

    /// <summary>Stage 5.1.4 — user-sourced revision must be a hex SHA (H-01.2.10).</summary>
    public static RevisionId ValidateRevision(string value, string paramName) =>
        RevisionId.TryParse(value, out var revision)
            ? revision
            : throw new ArgumentException(
                $"Git revision must be a hex SHA (H-05.1.4 / KBF-10-001) — got '{value}'.", paramName);

    /// <summary>Path arguments: relative repo paths, safe for a "--" pathspec.</summary>
    public static string ValidatePath(string value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Git path argument is required.", paramName);
        var v = value.Trim();
        if (v.StartsWith("-", StringComparison.Ordinal))
            throw new ArgumentException(
                "Git path argument must not start with '-' (option-injection guard, KBF-10-001).", paramName);
        if (Path.IsPathRooted(v))
            throw new ArgumentException(
                $"Git path argument must be repository-relative — got '{v}'.", paramName);
        if (v.Split('/', '\\').Any(segment => segment == ".."))
            throw new ArgumentException(
                "Git path argument must not escape the repository ('..' segments are rejected).", paramName);
        EnsureNoControlCharacters(v, paramName);
        return v;
    }

    /// <summary>Global argument guard (layer 4) — applied to EVERY argument token.</summary>
    public static void ValidateArguments(IEnumerable<string> arguments)
    {
        if (arguments is null)
            throw new ArgumentNullException(nameof(arguments));

        foreach (var argument in arguments)
        {
            if (argument is null)
                throw new ArgumentException("Git argument tokens must not be null.", nameof(arguments));

            if (ForbiddenOptionTokens.Contains(argument, StringComparer.Ordinal))
                throw new ArgumentException(
                    $"Git argument '{argument}' is a forbidden option (execution/reconfiguration " +
                    "guard — H-05.1, KBF-10-001).", nameof(arguments));

            EnsureNoControlCharacters(argument, nameof(arguments));
        }
    }

    private static void EnsureNoControlCharacters(string value, string paramName)
    {
        if (value.Any(c => char.IsControl(c)))
            throw new ArgumentException(
                "Git argument must not contain control characters.", paramName);
    }
}