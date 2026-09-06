using ISCM.Domain.Enums;
using System;

namespace ISCM.Domain.Entities;

/// <summary>
/// Defines a verification path for a SubControl.
/// 
/// Each path represents one independent acquisition mechanism
/// that can produce evidence for the same SubControl.
/// 
/// Phase 8 — Verification Architecture
/// 
/// Contract:
///   - PathId is unique within a SubControl scope.
///   - Source and AcquisitionMechanism together define the path identity.
///   - IndependenceClass declares how independent this path is from other paths.
///   - IsAvailable indicates whether the path can be executed on the current target.
///   - EvidenceSourceType is used for parser/normalizer routing.
/// 
/// A path that is declared Required but not Available produces an
/// explicit ERROR state (not silent pass) in the scanner.
/// </summary>
public class VerificationPath
{
    /// <summary>
    /// Unique identifier for this path within a SubControl.
    /// Format: "{SubControlId}-{PathIndex}" (e.g., "PWD-001.1-path-1")
    /// </summary>
    public string PathId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable source name (e.g., "Registry HKLM\\SAM", "net accounts").
    /// </summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>
    /// Technical acquisition mechanism description
    /// (e.g., "Registry API read", "Process execution: net.exe", "WMI query").
    /// </summary>
    public string AcquisitionMechanism { get; set; } = string.Empty;

    /// <summary>
    /// Independence classification.
    /// Determines how this path's result contributes to the final verdict
    /// in the agreement/disagreement engine (Phase 9).
    /// </summary>
    public IndependenceClass IndependenceClass { get; set; } = IndependenceClass.Undeclared;

    /// <summary>
    /// Whether this path is technically available on the target system.
    /// False paths produce explicit ERROR (not silent pass).
    /// </summary>
    public bool IsAvailable { get; set; } = true;

    /// <summary>
    /// Typed evidence source for parser/normalizer routing.
    /// </summary>
    public EvidenceSourceType EvidenceSourceType { get; set; } = EvidenceSourceType.Unknown;

    /// <summary>
    /// Optional: parser type name for pipeline dispatch.
    /// If null, default parser for EvidenceSourceType is used.
    /// </summary>
    public string? ParserTypeName { get; set; }

    /// <summary>
    /// Optional: normalizer type name for pipeline dispatch.
    /// If null, default normalizer for EvidenceSourceType is used.
    /// </summary>
    public string? NormalizerTypeName { get; set; }

    /// <summary>
    /// Whether this path is required for the SubControl verdict.
    /// A required but unavailable path produces ERROR.
    /// An optional unavailable path is silently skipped.
    /// </summary>
    public bool IsRequired { get; set; } = true;

    /// <summary>
    /// Optional description for diagnostics.
    /// </summary>
    public string? Description { get; set; }

    public VerificationPath() { }

    public VerificationPath(
        string pathId,
        string source,
        string acquisitionMechanism,
        IndependenceClass independenceClass,
        EvidenceSourceType evidenceSourceType,
        bool isAvailable = true,
        bool isRequired = true)
    {
        PathId = pathId ?? throw new ArgumentNullException(nameof(pathId));
        Source = source ?? string.Empty;
        AcquisitionMechanism = acquisitionMechanism ?? string.Empty;
        IndependenceClass = independenceClass;
        EvidenceSourceType = evidenceSourceType;
        IsAvailable = isAvailable;
        IsRequired = isRequired;
    }

    /// <summary>
    /// Factory: create a Registry-based path.
    /// </summary>
    public static VerificationPath RegistryPath(
        string pathId,
        string registryKey,
        IndependenceClass independenceClass = IndependenceClass.Independent,
        bool isRequired = true)
        => new(pathId, $"Registry {registryKey}", "Registry API read",
               independenceClass, EvidenceSourceType.Registry, isRequired: isRequired);

    /// <summary>
    /// Factory: create a PowerShell-based path.
    /// </summary>
    public static VerificationPath PowerShellPath(
        string pathId,
        string command,
        IndependenceClass independenceClass = IndependenceClass.SharedSource,
        bool isRequired = true)
        => new(pathId, $"PowerShell: {command}", "PowerShell process execution",
               independenceClass, EvidenceSourceType.PowerShell, isRequired: isRequired);

    /// <summary>
    /// Factory: create a Secedit-based path.
    /// </summary>
    public static VerificationPath SeceditPath(
        string pathId,
        string policyKey,
        IndependenceClass independenceClass = IndependenceClass.PartiallyIndependent,
        bool isRequired = true)
        => new(pathId, $"secedit {policyKey}", "secedit.exe export + parse",
               independenceClass, EvidenceSourceType.Secedit, isRequired: isRequired);

    /// <summary>
    /// Factory: create a NetAccounts-based path.
    /// </summary>
    public static VerificationPath NetAccountsPath(
        string pathId,
        string setting,
        IndependenceClass independenceClass = IndependenceClass.PartiallyIndependent,
        bool isRequired = true)
        => new(pathId, $"net accounts ({setting})", "net.exe accounts + parse",
               independenceClass, EvidenceSourceType.NetAccounts, isRequired: isRequired);

    /// <summary>
    /// Factory: create an Auditpol-based path.
    /// </summary>
    public static VerificationPath AuditpolPath(
        string pathId,
        string subcategory,
        IndependenceClass independenceClass = IndependenceClass.Independent,
        bool isRequired = true)
        => new(pathId, $"auditpol {subcategory}", "auditpol.exe /get + parse",
               independenceClass, EvidenceSourceType.Auditpol, isRequired: isRequired);
}