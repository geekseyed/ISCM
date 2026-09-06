using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.Entities;

/// <summary>
/// Defines a single SubControl within a ParentControl.
/// 
/// Phase 8.3: Added VerificationPath capability tracking:
///   - RequiredIndependenceClass: minimum independence level required
///   - Paths: declared verification paths for this SubControl
///   - IndependenceDeclarations: independence justification metadata
///   - Computed properties for capability validation
/// 
/// Backward compatibility:
///   - All existing properties preserved with same defaults
///   - New properties have safe defaults (empty lists, Undeclared)
///   - No existing catalog entries will break
/// </summary>
public class SubControlDefinition
{
    // =========================================================================
    // Identity & Classification (UNCHANGED)
    // =========================================================================

    public string SubControlId { get; set; } = string.Empty;

    public string SettingName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string ExpectedValue { get; set; } = string.Empty;

    public List<string> EvidenceSources { get; set; } = new();

    public CheckCategory Category { get; set; } = CheckCategory.System;

    public CheckSeverity Severity { get; set; } = CheckSeverity.Medium;

    public string? ApplicabilityRule { get; set; }

    public bool IsRequired { get; set; } = true;

    public string ParentControlId { get; set; } = string.Empty;

    // =========================================================================
    // Evaluation Contract (UNCHANGED from Phase 7)
    // =========================================================================

    public ExpectedValueType ExpectedValueType { get; set; } = ExpectedValueType.String;

    public Operator Operator { get; set; } = Operator.Equals;

    // =========================================================================
    // Path Capability (Phase 8.3 — NEW)
    // =========================================================================

    /// <summary>
    /// Required number of independent verification paths.
    /// Default 1 (single path is acceptable for many SubControls).
    /// 
    /// Contract (Section 2.1): Three-path verification is a capability,
    /// not an artificial requirement. Each SubControl declares its own requirement.
    /// </summary>
    public int RequiredPathCount { get; set; } = 1;

    /// <summary>
    /// Minimum independence class required for paths of this SubControl.
    /// Default Undeclared means any declared class is acceptable.
    /// 
    /// When set to a higher level (e.g., Independent), paths below this
    /// level do not count toward RequiredPathCount.
    /// </summary>
    public IndependenceClass RequiredIndependenceClass { get; set; } = IndependenceClass.Undeclared;

    /// <summary>
    /// Declared verification paths for this SubControl.
    /// Empty by default for backward compatibility with existing catalog.
    /// </summary>
    public List<VerificationPath> Paths { get; set; } = new();

    /// <summary>
    /// Independence declarations for the paths of this SubControl.
    /// Provides technical justification for each path's independence class.
    /// Empty by default.
    /// </summary>
    public List<PathIndependenceDeclaration> IndependenceDeclarations { get; set; } = new();

    /// <summary>
    /// Remediation actions available for this SubControl.
    /// </summary>
    public List<string> RemediationIds { get; set; } = new();

    // =========================================================================
    // Computed Properties (Phase 8.3 — NEW)
    // =========================================================================

    /// <summary>
    /// Number of paths that are technically available on the target system.
    /// Excludes paths marked IsAvailable = false.
    /// </summary>
    public int AvailablePathCount => Paths.Count(p => p.IsAvailable);

    /// <summary>
    /// Number of paths that count toward RequiredPathCount.
    /// 
    /// Excludes:
    ///   - Duplicate paths (they add no verification value)
    ///   - Paths below RequiredIndependenceClass (if declared)
    ///   - Unavailable paths
    /// 
    /// Contract (Section 2.1): A SubControl requiring only one technically
    /// valid acquisition method must not be artificially assigned fake paths.
    /// </summary>
    public int CountedPathCount => Paths.Count(p => IsPathCounted(p));

    /// <summary>
    /// Number of paths with IndependenceClass = Independent.
    /// </summary>
    public int IndependentPathCount => Paths.Count(p => p.IndependenceClass == IndependenceClass.Independent);

    /// <summary>
    /// Whether the SubControl's declared paths satisfy the RequiredPathCount.
    /// 
    /// True when CountedPathCount >= RequiredPathCount.
    /// False otherwise (scanner must produce ERROR for required SubControls).
    /// </summary>
    public bool MeetsPathCountRequirement => CountedPathCount >= RequiredPathCount;

    /// <summary>
    /// Whether all counted paths meet the RequiredIndependenceClass.
    /// True when RequiredIndependenceClass is Undeclared (no requirement).
    /// </summary>
    public bool MeetsIndependenceRequirement
    {
        get
        {
            if (RequiredIndependenceClass == IndependenceClass.Undeclared)
                return true;

            return Paths
                .Where(p => p.IsAvailable && p.IndependenceClass != IndependenceClass.Duplicate)
                .All(p => p.IndependenceClass >= RequiredIndependenceClass);
        }
    }

    // =========================================================================
    // Helper Methods (Phase 8.3 — NEW)
    // =========================================================================

    /// <summary>
    /// Determines whether a path counts toward RequiredPathCount.
    /// 
    /// A path is counted when:
    ///   1. It is available (IsAvailable = true)
    ///   2. It is not a duplicate (IndependenceClass != Duplicate)
    ///   3. It meets the RequiredIndependenceClass (if declared)
    /// </summary>
    private bool IsPathCounted(VerificationPath path)
    {
        if (path == null)
            return false;

        if (!path.IsAvailable)
            return false;

        if (path.IndependenceClass == IndependenceClass.Duplicate)
            return false;

        if (RequiredIndependenceClass != IndependenceClass.Undeclared &&
            path.IndependenceClass < RequiredIndependenceClass)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Gets paths that count toward RequiredPathCount.
    /// </summary>
    public List<VerificationPath> GetCountedPaths()
        => Paths.Where(p => IsPathCounted(p)).ToList();

    /// <summary>
    /// Gets paths that are available (regardless of independence class).
    /// </summary>
    public List<VerificationPath> GetAvailablePaths()
        => Paths.Where(p => p.IsAvailable).ToList();

    /// <summary>
    /// Gets required paths that are NOT available.
    /// Used by scanner to produce explicit ERROR for missing required paths.
    /// </summary>
    public List<VerificationPath> GetRequiredUnavailablePaths()
        => Paths.Where(p => p.IsRequired && !p.IsAvailable).ToList();

    /// <summary>
    /// Gets the independence declaration for a specific path.
    /// Returns null if no declaration exists for the path.
    /// </summary>
    public PathIndependenceDeclaration? GetIndependenceDeclaration(string pathId)
        => IndependenceDeclarations.FirstOrDefault(d => d.PathId == pathId);

    /// <summary>
    /// Validates the path capability configuration.
    /// Returns (IsValid, Errors, Warnings).
    /// </summary>
    public (bool IsValid, List<string> Errors, List<string> Warnings) ValidatePathCapability()
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        // Rule 1: RequiredPathCount must be at least 1
        if (RequiredPathCount < 1)
        {
            errors.Add($"SubControl '{SubControlId}': RequiredPathCount must be at least 1.");
        }

        // Rule 2: Paths should not be empty when RequiredPathCount > 0
        if (RequiredPathCount > 0 && Paths.Count == 0)
        {
            warnings.Add($"SubControl '{SubControlId}': RequiredPathCount={RequiredPathCount} but no paths declared.");
        }

        // Rule 3: Check path count requirement
        if (Paths.Count > 0 && !MeetsPathCountRequirement)
        {
            warnings.Add($"SubControl '{SubControlId}': CountedPathCount={CountedPathCount} < RequiredPathCount={RequiredPathCount}.");
        }

        // Rule 4: Check independence requirement
        if (Paths.Count > 0 && !MeetsIndependenceRequirement)
        {
            warnings.Add($"SubControl '{SubControlId}': Not all counted paths meet RequiredIndependenceClass={RequiredIndependenceClass}.");
        }

        // Rule 5: Check independence declarations for non-duplicate paths
        foreach (var path in Paths.Where(p => p.IndependenceClass != IndependenceClass.Duplicate))
        {
            var declaration = GetIndependenceDeclaration(path.PathId);
            if (declaration == null && path.IndependenceClass != IndependenceClass.Undeclared)
            {
                warnings.Add($"SubControl '{SubControlId}': Path '{path.PathId}' has IndependenceClass={path.IndependenceClass} but no declaration.");
            }
        }

        // Rule 6: Validate independence declarations
        foreach (var declaration in IndependenceDeclarations)
        {
            var (isValid, declErrors, _) = declaration.Validate();
            if (!isValid)
            {
                errors.AddRange(declErrors.Select(e => $"SubControl '{SubControlId}': {e}"));
            }
        }

        return (errors.Count == 0, errors, warnings);
    }
}