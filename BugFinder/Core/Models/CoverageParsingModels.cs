using ISCM.BugFinder.Core.Services;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-04.2: Coverage Artifact Parsing Models
/// (audit KBF-06-002: CoverageReportParser expected a specific JSON tree;
/// no format negotiation — upstream changes could silently reduce data).
///
/// Parses the coverlet XPlat cobertura XML (the H-04.1 authoritative
/// collector's output) into a structured hierarchy with REAL per-line
/// hit counts — the raw material for the per-test spectrum (H-04.5)
/// and the element universe (H-04.4).
///
/// EXPLICIT STATES (H-01.4): FileMissing / Corrupt / UnsupportedFormat
/// / NoModules — never a fabricated empty document.
/// </summary>
public enum CoverageParsingStatus
{
    Parsed,
    FileMissing,
    Corrupt,
    UnsupportedFormat,
    NoModules
}

/// <summary>One covered/instrumented source line (Stage 4.2.5).</summary>
public sealed class CoverageLine
{
    /// <summary>1-based line number in the source file (cobertura @number).</summary>
    public int LineNumber { get; init; }

    /// <summary>Execution hit count from coverlet (0 = instrumented but not hit).</summary>
    public int Hits { get; init; }

    public bool IsCovered => Hits > 0;

    /// <summary>The condition coverage, when the line is a branch (cobertura @condition-coverage).</summary>
    public string? ConditionCoverage { get; init; }
}

/// <summary>Stage 4.2.4 — one method with its lines.</summary>
public sealed class CoverageMethod
{
    public string MethodName { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;
    public decimal LineRate { get; init; }
    public IReadOnlyList<CoverageLine> Lines { get; init; } = Array.Empty<CoverageLine>();
}

/// <summary>Stage 4.2.3 — one class with its methods and flattened lines.</summary>
public sealed class CoverageClass
{
    public string ClassName { get; init; } = string.Empty;

    /// <summary>The source file this class lives in (cobertura @filename, normalized).</summary>
    public string SourceFilePath { get; init; } = string.Empty;

    public decimal LineRate { get; init; }
    public IReadOnlyList<CoverageMethod> Methods { get; init; } = Array.Empty<CoverageMethod>();

    /// <summary>Flattened lines across all methods (deduped by line number).</summary>
    public IReadOnlyList<CoverageLine> AllLines { get; init; } = Array.Empty<CoverageLine>();
}

/// <summary>Stage 4.2.2 — one module (assembly) with its classes.</summary>
public sealed class CoverageModule
{
    public string ModuleName { get; init; } = string.Empty;
    public IReadOnlyList<CoverageClass> Classes { get; init; } = Array.Empty<CoverageClass>();
}

/// <summary>The parsed coverage document (Stage 4.2 output).</summary>
public sealed class CoverageDocument
{
    public CoverageParsingStatus Status { get; init; }
    public string SourceArtifactPath { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;   // mandatory for non-Parsed

    /// <summary>The collector that produced this artifact (provenance, H-04.7).</summary>
    public string CollectorName { get; init; } = CoverageCollectorService.AuthoritativeCollector;

    public IReadOnlyList<CoverageModule> Modules { get; init; } = Array.Empty<CoverageModule>();

    public int TotalModules { get; init; }
    public int TotalClasses { get; init; }
    public int TotalMethods { get; init; }
    public int TotalLines { get; init; }
    public int CoveredLines { get; init; }
    public decimal LineRate { get; init; }
}