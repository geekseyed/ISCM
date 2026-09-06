using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Value Object describing the independence characteristics of a VerificationPath.
/// 
/// Phase 8 — Verification Architecture, Sub-Phase 8.2
/// 
/// Contract (from Final Engineering Specification, Section 2.2):
///   - Independence must be evaluated based on:
///       source, acquisition mechanism, underlying authoritative state,
///       failure mode, implementation dependency.
///   - A path must not be labelled "Independent" unless its independence
///     is technically defensible.
///   - PowerShell / Registry / WMI are technology mechanisms, not
///     automatically independent.
/// 
/// This VO is:
///   - Immutable after construction
///   - Stored alongside VerificationPath in the catalog or at scan time
///   - Consumed by the Agreement Engine (Phase 9) to weight path results
///   - Used for audit / UI to show WHY a path is classified as it is
/// 
/// Design rules:
///   1. Justification is REQUIRED for all non-Duplicate classes.
///   2. SharedStateDescription is REQUIRED when IndependenceClass = SharedSource.
///   3. CorrelatedPathIds lists paths that share state or failure modes.
///   4. FailureModeIsolation = true means a path's failure does not imply
///      other paths will fail (genuinely independent failure modes).
/// </summary>
public sealed class PathIndependenceDeclaration
{
    // =========================================================================
    // Identity
    // =========================================================================

    /// <summary>
    /// The PathId this declaration describes.
    /// Must match a VerificationPath.PathId.
    /// </summary>
    public string PathId { get; }

    /// <summary>
    /// The SubControlId this declaration belongs to (for scope).
    /// </summary>
    public string SubControlId { get; }

    /// <summary>
    /// Declared independence classification.
    /// </summary>
    public IndependenceClass IndependenceClass { get; }

    // =========================================================================
    // Justification (mandatory audit trail)
    // =========================================================================

    /// <summary>
    /// Human-readable technical justification for the declared class.
    /// Must not be empty for Independent / PartiallyIndependent / SharedSource.
    /// </summary>
    public string Justification { get; }

    /// <summary>
    /// Description of the shared underlying state with other paths
    /// (only meaningful when IndependenceClass = SharedSource).
    /// </summary>
    public string? SharedStateDescription { get; }

    /// <summary>
    /// Description of the distinct authoritative state
    /// (only meaningful when IndependenceClass = Independent).
    /// </summary>
    public string? DistinctStateDescription { get; }

    // =========================================================================
    // Correlation
    // =========================================================================

    /// <summary>
    /// List of PathIds that this path is correlated with
    /// (same state, same failure mode, or duplicate).
    /// Empty list means no known correlation.
    /// </summary>
    public IReadOnlyList<string> CorrelatedPathIds { get; }

    // =========================================================================
    // Failure mode isolation
    // =========================================================================

    /// <summary>
    /// Whether a failure of this path does NOT imply other paths will fail.
    /// True = genuinely independent failure modes.
    /// False = failure may cascade to correlated paths.
    /// </summary>
    public bool FailureModeIsolation { get; }

    // =========================================================================
    // Audit metadata
    // =========================================================================

    /// <summary>
    /// When this declaration was made (UTC).
    /// </summary>
    public DateTime DeclaredAtUtc { get; }

    /// <summary>
    /// Who or what made this declaration (engineer, catalog seeder, auto-classifier).
    /// </summary>
    public string DeclaredBy { get; }

    /// <summary>
    /// Optional technical notes for diagnostics.
    /// </summary>
    public string? TechnicalNotes { get; }

    // =========================================================================
    // Constructor (private — use factory methods)
    // =========================================================================

    private PathIndependenceDeclaration(
        string pathId,
        string subControlId,
        IndependenceClass independenceClass,
        string justification,
        string? sharedStateDescription,
        string? distinctStateDescription,
        IReadOnlyList<string> correlatedPathIds,
        bool failureModeIsolation,
        string declaredBy,
        string? technicalNotes)
    {
        PathId = pathId ?? throw new ArgumentNullException(nameof(pathId));
        SubControlId = subControlId ?? throw new ArgumentNullException(nameof(subControlId));
        IndependenceClass = independenceClass;
        Justification = justification ?? string.Empty;
        SharedStateDescription = sharedStateDescription;
        DistinctStateDescription = distinctStateDescription;
        CorrelatedPathIds = correlatedPathIds ?? Array.Empty<string>();
        FailureModeIsolation = failureModeIsolation;
        DeclaredAtUtc = DateTime.UtcNow;
        DeclaredBy = declaredBy ?? "unknown";
        TechnicalNotes = technicalNotes;
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /// <summary>
    /// Validates the declaration is internally consistent.
    /// Returns (IsValid, Errors).
    /// 
    /// Rules:
    ///   - Justification required for non-Duplicate, non-Undeclared classes
    ///   - SharedStateDescription required for SharedSource
    ///   - CorrelatedPathIds must not contain self
    ///   - Independent class should have FailureModeIsolation = true (warning, not error)
    /// </summary>
    public (bool IsValid, List<string> Errors, List<string> Warnings) Validate()
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        // Rule 1: Justification required
        if (IndependenceClass != IndependenceClass.Duplicate &&
            IndependenceClass != IndependenceClass.Undeclared &&
            string.IsNullOrWhiteSpace(Justification))
        {
            errors.Add($"PathId '{PathId}': Justification is required for IndependenceClass={IndependenceClass}.");
        }

        // Rule 2: SharedStateDescription required for SharedSource
        if (IndependenceClass == IndependenceClass.SharedSource &&
            string.IsNullOrWhiteSpace(SharedStateDescription))
        {
            errors.Add($"PathId '{PathId}': SharedStateDescription is required for IndependenceClass=SharedSource.");
        }

        // Rule 3: CorrelatedPathIds must not contain self
        if (CorrelatedPathIds.Contains(PathId))
        {
            errors.Add($"PathId '{PathId}': CorrelatedPathIds must not contain self.");
        }

        // Rule 4: Independent should have FailureModeIsolation = true (warning)
        if (IndependenceClass == IndependenceClass.Independent && !FailureModeIsolation)
        {
            warnings.Add($"PathId '{PathId}': IndependenceClass=Independent typically requires FailureModeIsolation=true.");
        }

        // Rule 5: Duplicate should have at least one correlated path (warning)
        if (IndependenceClass == IndependenceClass.Duplicate && CorrelatedPathIds.Count == 0)
        {
            warnings.Add($"PathId '{PathId}': IndependenceClass=Duplicate typically has at least one correlated path.");
        }

        return (errors.Count == 0, errors, warnings);
    }

    // =========================================================================
    // Factory methods (preferred public construction API)
    // =========================================================================

    /// <summary>
    /// Declare a genuinely independent path.
    /// 
    /// Use when:
    ///   - Different authoritative state source
    ///   - Different acquisition mechanism
    ///   - Different failure mode
    /// 
    /// Example: Event Log audit trail vs Registry configuration.
    /// </summary>
    public static PathIndependenceDeclaration ForIndependent(
        string pathId,
        string subControlId,
        string justification,
        string distinctStateDescription,
        bool failureModeIsolation = true,
        string declaredBy = "engineer",
        string? technicalNotes = null)
    {
        if (string.IsNullOrWhiteSpace(justification))
            throw new ArgumentException("Justification is required for Independent path.", nameof(justification));
        if (string.IsNullOrWhiteSpace(distinctStateDescription))
            throw new ArgumentException("DistinctStateDescription is required for Independent path.", nameof(distinctStateDescription));

        return new PathIndependenceDeclaration(
            pathId, subControlId,
            IndependenceClass.Independent,
            justification,
            sharedStateDescription: null,
            distinctStateDescription: distinctStateDescription,
            correlatedPathIds: Array.Empty<string>(),
            failureModeIsolation: failureModeIsolation,
            declaredBy: declaredBy,
            technicalNotes: technicalNotes);
    }

    /// <summary>
    /// Declare a path that shares underlying state with other paths
    /// but uses a different acquisition mechanism.
    /// 
    /// Use when:
    ///   - Same authoritative state source (e.g., same registry key)
    ///   - Different API/tool reads it
    /// 
    /// Example: Registry API read vs PowerShell Get-ItemProperty on same key.
    /// </summary>
    public static PathIndependenceDeclaration ForSharedSource(
        string pathId,
        string subControlId,
        string justification,
        string sharedStateDescription,
        IReadOnlyList<string> correlatedPathIds,
        bool failureModeIsolation = false,
        string declaredBy = "engineer",
        string? technicalNotes = null)
    {
        if (string.IsNullOrWhiteSpace(justification))
            throw new ArgumentException("Justification is required for SharedSource path.", nameof(justification));
        if (string.IsNullOrWhiteSpace(sharedStateDescription))
            throw new ArgumentException("SharedStateDescription is required for SharedSource path.", nameof(sharedStateDescription));
        if (correlatedPathIds == null || correlatedPathIds.Count == 0)
            throw new ArgumentException("CorrelatedPathIds must not be empty for SharedSource path.", nameof(correlatedPathIds));

        return new PathIndependenceDeclaration(
            pathId, subControlId,
            IndependenceClass.SharedSource,
            justification,
            sharedStateDescription: sharedStateDescription,
            distinctStateDescription: null,
            correlatedPathIds: correlatedPathIds.ToArray(),
            failureModeIsolation: failureModeIsolation,
            declaredBy: declaredBy,
            technicalNotes: technicalNotes);
    }

    /// <summary>
    /// Declare a partially independent path.
    /// 
    /// Use when:
    ///   - Different acquisition mechanism and different authoritative source
    ///   - But some failure modes may still correlate
    /// 
    /// Example: secedit export vs net accounts command for security policy.
    /// </summary>
    public static PathIndependenceDeclaration ForPartiallyIndependent(
        string pathId,
        string subControlId,
        string justification,
        IReadOnlyList<string>? correlatedPathIds = null,
        bool failureModeIsolation = false,
        string declaredBy = "engineer",
        string? technicalNotes = null)
    {
        if (string.IsNullOrWhiteSpace(justification))
            throw new ArgumentException("Justification is required for PartiallyIndependent path.", nameof(justification));

        return new PathIndependenceDeclaration(
            pathId, subControlId,
            IndependenceClass.PartiallyIndependent,
            justification,
            sharedStateDescription: null,
            distinctStateDescription: null,
            correlatedPathIds: correlatedPathIds?.ToArray() ?? Array.Empty<string>(),
            failureModeIsolation: failureModeIsolation,
            declaredBy: declaredBy,
            technicalNotes: technicalNotes);
    }

    /// <summary>
    /// Declare a duplicate path.
    /// 
    /// Use when:
    ///   - Path produces the same evidence as another path
    ///   - Wrapper, copy, or redundant execution
    /// 
    /// Duplicates must NOT count toward required path count.
    /// </summary>
    public static PathIndependenceDeclaration ForDuplicate(
        string pathId,
        string subControlId,
        string justification,
        IReadOnlyList<string> duplicatedOfPathIds,
        string declaredBy = "engineer",
        string? technicalNotes = null)
    {
        if (string.IsNullOrWhiteSpace(justification))
            throw new ArgumentException("Justification is required for Duplicate path.", nameof(justification));
        if (duplicatedOfPathIds == null || duplicatedOfPathIds.Count == 0)
            throw new ArgumentException("DuplicatedOfPathIds must not be empty for Duplicate path.", nameof(duplicatedOfPathIds));

        return new PathIndependenceDeclaration(
            pathId, subControlId,
            IndependenceClass.Duplicate,
            justification,
            sharedStateDescription: null,
            distinctStateDescription: null,
            correlatedPathIds: duplicatedOfPathIds.ToArray(),
            failureModeIsolation: false,
            declaredBy: declaredBy,
            technicalNotes: technicalNotes);
    }

    /// <summary>
    /// Declare an undeclared / not-yet-classified path.
    /// Use as a sentinel until classification is completed.
    /// </summary>
    public static PathIndependenceDeclaration Undeclared(
        string pathId,
        string subControlId,
        string declaredBy = "pending")
    {
        return new PathIndependenceDeclaration(
            pathId, subControlId,
            IndependenceClass.Undeclared,
            justification: "Classification pending",
            sharedStateDescription: null,
            distinctStateDescription: null,
            correlatedPathIds: Array.Empty<string>(),
            failureModeIsolation: false,
            declaredBy: declaredBy,
            technicalNotes: null);
    }

    // =========================================================================
    // Overrides
    // =========================================================================

    public override string ToString()
        => $"[PathId={PathId}, Class={IndependenceClass}, Correlations={CorrelatedPathIds.Count}, Isolated={FailureModeIsolation}]";

    public override bool Equals(object? obj)
    {
        if (obj is not PathIndependenceDeclaration other)
            return false;

        return PathId == other.PathId &&
               SubControlId == other.SubControlId &&
               IndependenceClass == other.IndependenceClass &&
               FailureModeIsolation == other.FailureModeIsolation &&
               CorrelatedPathIds.SequenceEqual(other.CorrelatedPathIds);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + (PathId?.GetHashCode() ?? 0);
            hash = hash * 31 + (SubControlId?.GetHashCode() ?? 0);
            hash = hash * 31 + IndependenceClass.GetHashCode();
            hash = hash * 31 + FailureModeIsolation.GetHashCode();
            return hash;
        }
    }
}