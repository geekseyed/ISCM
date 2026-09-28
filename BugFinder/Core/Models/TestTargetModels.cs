namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-03.4: Target Test Discovery Models
/// (audit KBF-01-004: the default test project was hard-coded to
/// ISCM.Tests/ISCM.Tests.csproj — the engine was coupled to one
/// repository layout).
///
/// The service resolves test targets from EXPLICIT configuration
/// (authoritative when provided) or from the solution inventory.
/// Detection is documented per-target via DetectionReason — never
/// silently guessed.
/// </summary>

/// <summary>One discovered test target with its preserved identity (3.4.5).</summary>
public sealed class TestTarget
{
    /// <summary>Project name as declared in the solution.</summary>
    public string ProjectName { get; init; } = string.Empty;

    /// <summary>Project file path as declared in the solution (relative to the solution dir).</summary>
    public string ProjectFilePath { get; init; } = string.Empty;

    /// <summary>Solution-assigned project GUID.</summary>
    public string ProjectGuid { get; init; } = string.Empty;

    /// <summary>Solution project-type GUID (C# classic / SDK-style).</summary>
    public string ProjectTypeGuid { get; init; } = string.Empty;

    /// <summary>True when this target should run as a test assembly.</summary>
    public bool IsTestProject { get; init; }

    /// <summary>WHY this target was (or was not) classified as a test project —
    /// documented, never a silent guess (H-01.4 vocabulary in spirit).</summary>
    public string DetectionReason { get; init; } = string.Empty;
}

/// <summary>Detection reason vocabulary (H-01.4-style explicit states).</summary>
public static class TestTargetDetectionReason
{
    public const string ExplicitConfiguration = "explicit configuration (authoritative)";
    public const string NameConvention = "name convention '*.Tests' (v1 heuristic)";
    public const string NotDetected = "no test signal (explicit list absent, name convention miss)";
}

/// <summary>Discovery report — deterministic ordering throughout.</summary>
public sealed class TestTargetDiscoveryReport
{
    /// <summary>All C# projects in the solution inventory (ordinal by path).</summary>
    public IReadOnlyList<TestTarget> AllProjects { get; init; } = Array.Empty<TestTarget>();

    /// <summary>Targets that should run as test assemblies (3.4.4: possibly many).</summary>
    public IReadOnlyList<TestTarget> TestProjects { get; init; } = Array.Empty<TestTarget>();

    public string SolutionPath { get; init; } = string.Empty;

    public int TotalProjectCount { get; init; }
    public int TestProjectCount { get; init; }

    /// <summary>Skipped non-C# entries, unmatched explicit entries, empty
    /// inventories — everything the caller should know, explicitly.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}