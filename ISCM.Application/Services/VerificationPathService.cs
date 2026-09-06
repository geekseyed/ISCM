using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Services;

/// <summary>
/// Service for managing and validating VerificationPath capability
/// at the SubControl level.
/// 
/// Phase 8.3 — Sub-Phase 8.3.2
/// 
/// Responsibilities:
///   1. Validate path capability configuration
///   2. Get available/counted paths for a SubControl
///   3. Check independence requirement compliance
///   4. Produce PathCapabilityReport for audit/UI
/// 
/// Contract (from Final Engineering Specification, Section 8.3):
///   - Not every SubControl necessarily has three genuinely independent mechanisms.
///   - Catalog must record: ThreePathRequired, ThreePathAvailable, PathCount, IndependenceClass.
///   - A missing technically possible required path is a verification failure,
///     not an invisible omission.
/// 
/// This service does NOT execute paths. Execution is done by the scanner (Phase 10).
/// This service only validates and reports path capability.
/// </summary>
public class VerificationPathService
{
    // =========================================================================
    // Capability Validation
    // =========================================================================

    /// <summary>
    /// Validates the path capability of a SubControl.
    /// Returns a PathCapabilityReport with details for audit/UI.
    /// </summary>
    public PathCapabilityReport ValidatePathCapability(SubControlDefinition subControl)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        var report = new PathCapabilityReport
        {
            SubControlId = subControl.SubControlId,
            RequiredPathCount = subControl.RequiredPathCount,
            RequiredIndependenceClass = subControl.RequiredIndependenceClass,
            DeclaredPathCount = subControl.Paths.Count,
            AvailablePathCount = subControl.AvailablePathCount,
            CountedPathCount = subControl.CountedPathCount,
            IndependentPathCount = subControl.IndependentPathCount,
            MeetsPathCountRequirement = subControl.MeetsPathCountRequirement,
            MeetsIndependenceRequirement = subControl.MeetsIndependenceRequirement,
            EvaluatedAtUtc = DateTime.UtcNow
        };

        // Run SubControlDefinition.ValidatePathCapability
        var (isValid, errors, warnings) = subControl.ValidatePathCapability();
        report.IsValid = isValid;
        report.Errors.AddRange(errors);
        report.Warnings.AddRange(warnings);

        // Additional service-level validations
        ValidatePathUniqueness(subControl, report);
        ValidateIndependenceDeclarations(subControl, report);
        ValidateRequiredPathsAvailability(subControl, report);

        return report;
    }

    // =========================================================================
    // Path Retrieval
    // =========================================================================

    /// <summary>
    /// Gets paths that count toward RequiredPathCount
    /// (available, non-duplicate, meeting independence requirement).
    /// </summary>
    public List<VerificationPath> GetCountedPaths(SubControlDefinition subControl)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        return subControl.GetCountedPaths();
    }

    /// <summary>
    /// Gets all available paths (regardless of independence class).
    /// </summary>
    public List<VerificationPath> GetAvailablePaths(SubControlDefinition subControl)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        return subControl.GetAvailablePaths();
    }

    /// <summary>
    /// Gets required paths that are not available.
    /// Scanner must produce explicit ERROR for these paths.
    /// </summary>
    public List<VerificationPath> GetRequiredUnavailablePaths(SubControlDefinition subControl)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        return subControl.GetRequiredUnavailablePaths();
    }

    /// <summary>
    /// Gets the independence declaration for a specific path.
    /// </summary>
    public PathIndependenceDeclaration? GetIndependenceDeclaration(
        SubControlDefinition subControl,
        string pathId)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        return subControl.GetIndependenceDeclaration(pathId);
    }

    // =========================================================================
    // Independence Compliance
    // =========================================================================

    /// <summary>
    /// Checks whether a SubControl meets its independence requirement.
    /// Returns (IsCompliant, Reason).
    /// </summary>
    public (bool IsCompliant, string Reason) CheckIndependenceCompliance(SubControlDefinition subControl)
    {
        if (subControl == null)
            throw new ArgumentNullException(nameof(subControl));

        if (subControl.RequiredIndependenceClass == IndependenceClass.Undeclared)
        {
            return (true, "No independence requirement declared. All declared classes acceptable.");
        }

        var countedPaths = subControl.GetCountedPaths();

        if (countedPaths.Count == 0)
        {
            return (false, $"No counted paths found for SubControl '{subControl.SubControlId}'.");
        }

        var belowRequirement = countedPaths
            .Where(p => p.IndependenceClass < subControl.RequiredIndependenceClass)
            .ToList();

        if (belowRequirement.Count > 0)
        {
            var pathIds = string.Join(", ", belowRequirement.Select(p => p.PathId));
            return (false,
                $"Paths below RequiredIndependenceClass={subControl.RequiredIndependenceClass}: {pathIds}.");
        }

        return (true,
            $"All {countedPaths.Count} counted paths meet RequiredIndependenceClass={subControl.RequiredIndependenceClass}.");
    }

    // =========================================================================
    // Private Validation Helpers
    // =========================================================================

    /// <summary>
    /// Validates that PathIds are unique within a SubControl.
    /// </summary>
    private void ValidatePathUniqueness(SubControlDefinition subControl, PathCapabilityReport report)
    {
        var duplicatePathIds = subControl.Paths
            .GroupBy(p => p.PathId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicatePathIds.Count > 0)
        {
            report.Errors.Add(
                $"SubControl '{subControl.SubControlId}': Duplicate PathIds: {string.Join(", ", duplicatePathIds)}.");
            report.IsValid = false;
        }
    }

    /// <summary>
    /// Validates that independence declarations reference valid paths.
    /// </summary>
    private void ValidateIndependenceDeclarations(SubControlDefinition subControl, PathCapabilityReport report)
    {
        var pathIds = new HashSet<string>(subControl.Paths.Select(p => p.PathId));

        foreach (var declaration in subControl.IndependenceDeclarations)
        {
            if (!pathIds.Contains(declaration.PathId))
            {
                report.Warnings.Add(
                    $"SubControl '{subControl.SubControlId}': IndependenceDeclaration references unknown PathId '{declaration.PathId}'.");
            }
        }
    }

    /// <summary>
    /// Validates that required paths are available.
    /// </summary>
    private void ValidateRequiredPathsAvailability(SubControlDefinition subControl, PathCapabilityReport report)
    {
        var unavailableRequired = subControl.GetRequiredUnavailablePaths();

        if (unavailableRequired.Count > 0)
        {
            var pathIds = string.Join(", ", unavailableRequired.Select(p => p.PathId));
            report.Warnings.Add(
                $"SubControl '{subControl.SubControlId}': Required paths not available: {pathIds}. " +
                "Scanner will produce explicit ERROR for these paths.");
        }
    }
}

// =========================================================================
// PathCapabilityReport — result VO for path capability validation
// =========================================================================

/// <summary>
/// Report describing the path capability of a SubControl.
/// 
/// Phase 8.3 — Sub-Phase 8.3.2
/// 
/// Used by:
///   - Scanner (to decide ERROR vs continue)
///   - UI (to show path capability details)
///   - Audit (to track capability compliance)
/// </summary>
public class PathCapabilityReport
{
    public string SubControlId { get; set; } = string.Empty;

    public int RequiredPathCount { get; set; }

    public IndependenceClass RequiredIndependenceClass { get; set; } = IndependenceClass.Undeclared;

    public int DeclaredPathCount { get; set; }

    public int AvailablePathCount { get; set; }

    public int CountedPathCount { get; set; }

    public int IndependentPathCount { get; set; }

    public bool MeetsPathCountRequirement { get; set; }

    public bool MeetsIndependenceRequirement { get; set; }

    public bool IsValid { get; set; }

    public List<string> Errors { get; set; } = new();

    public List<string> Warnings { get; set; } = new();

    public DateTime EvaluatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Overall capability status.
    /// </summary>
    public PathCapabilityStatus Status
    {
        get
        {
            if (!IsValid || Errors.Count > 0)
                return PathCapabilityStatus.Invalid;

            if (!MeetsPathCountRequirement)
                return PathCapabilityStatus.InsufficientPaths;

            if (!MeetsIndependenceRequirement)
                return PathCapabilityStatus.InsufficientIndependence;

            return PathCapabilityStatus.Satisfied;
        }
    }

    public override string ToString()
        => $"[SubControl={SubControlId}, Status={Status}, Counted={CountedPathCount}/{RequiredPathCount}, Independence={MeetsIndependenceRequirement}]";
}

/// <summary>
/// Overall status of path capability for a SubControl.
/// </summary>
public enum PathCapabilityStatus
{
    /// <summary>Path capability is satisfied (all requirements met).</summary>
    Satisfied = 0,

    /// <summary>Path configuration is invalid (errors present).</summary>
    Invalid = 1,

    /// <summary>Not enough counted paths to meet RequiredPathCount.</summary>
    InsufficientPaths = 2,

    /// <summary>Counted paths do not meet RequiredIndependenceClass.</summary>
    InsufficientIndependence = 3
}