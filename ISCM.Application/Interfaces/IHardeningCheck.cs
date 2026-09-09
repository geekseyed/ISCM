using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Interface for hardening checks.
/// 
/// Phase 11.5: Simplified to metadata-only interface.
/// All evaluation logic moved to Scanner via IEvidenceCollector pattern.
/// 
/// Contract:
/// - Checks provide metadata (CheckId, Name, Category, Severity)
/// - Checks implement IEvidenceCollector for evidence collection
/// - Scanner evaluates using catalog metadata and typed pipeline
/// </summary>
public interface IHardeningCheck
{
    /// <summary>
    /// Unique identifier for this check (e.g., "PWD-001").
    /// </summary>
    string CheckId { get; }

    /// <summary>
    /// Human-readable name of this check.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Category of this check (Account, System, Network, Audit).
    /// </summary>
    CheckCategory Category { get; }

    /// <summary>
    /// Severity of this check (Critical, High, Medium, Low).
    /// </summary>
    CheckSeverity Severity { get; }
}