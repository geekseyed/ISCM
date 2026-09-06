using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.Entities;

/// <summary>
/// Result of evaluating a single SubControl.
/// 
/// Phase 8.4: Added path integration support:
///   - PathCapabilityReport: stores capability validation result
///   - Helper methods for PathResult management
///   - VerificationResults (List<PathResult>) stores per-path execution results
/// 
/// Backward compatibility:
///   - All existing properties preserved
///   - New properties have safe defaults
/// </summary>
public class SubControlResult
{
    // =========================================================================
    // Identity & Status
    // =========================================================================

    public string SubControlId { get; set; } = string.Empty;

    public CheckStatus Status { get; set; } = CheckStatus.Unknown;

    // =========================================================================
    // Evidence
    // =========================================================================

    public List<Evidence> EvidenceItems { get; set; } = new();

    public List<string> EvidenceReferences { get; set; } = new();

    // =========================================================================
    // Verification Results (Phase 8.4)
    // =========================================================================

    /// <summary>
    /// Results of each verification path execution.
    /// One PathResult per VerificationPath per scan.
    /// </summary>
    public List<PathResult> VerificationResults { get; set; } = new();

    /// <summary>
    /// Path capability validation report for this SubControl.
    /// Null if capability validation was not performed.
    /// </summary>
    public PathCapabilityReport? PathCapabilityReport { get; set; }

    // =========================================================================
    // Timing
    // =========================================================================

    public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;

    // =========================================================================
    // Helper Methods (Phase 8.4)
    // =========================================================================

    /// <summary>
    /// Adds a PathResult to VerificationResults.
    /// </summary>
    public void AddPathResult(PathResult pathResult)
    {
        if (pathResult == null)
            throw new ArgumentNullException(nameof(pathResult));

        VerificationResults.Add(pathResult);
    }

    /// <summary>
    /// Gets path results filtered by status.
    /// </summary>
    public List<PathResult> GetPathResultsByStatus(CheckStatus status)
        => VerificationResults.Where(p => p.Status == status).ToList();

    /// <summary>
    /// Gets path results that were skipped.
    /// </summary>
    public List<PathResult> GetSkippedPathResults()
        => VerificationResults.Where(p => p.WasSkipped).ToList();

    /// <summary>
    /// Count of path results.
    /// </summary>
    public int PathResultCount => VerificationResults.Count;

    /// <summary>
    /// Whether all path results are Pass.
    /// </summary>
    public bool AllPathsPass =>
        VerificationResults.Count > 0 &&
        VerificationResults.All(p => p.Status == CheckStatus.Pass);

    /// <summary>
    /// Whether any path result is Error.
    /// </summary>
    public bool AnyPathError =>
        VerificationResults.Any(p => p.Status == CheckStatus.Error);

    /// <summary>
    /// Whether any path result is Fail.
    /// </summary>
    public bool AnyPathFail =>
        VerificationResults.Any(p => p.Status == CheckStatus.Fail);

    /// <summary>
    /// Gets a PathResult by PathId.
    /// </summary>
    public PathResult? GetPathResult(string pathId)
        => VerificationResults.FirstOrDefault(p => p.PathId == pathId);
}