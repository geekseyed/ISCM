namespace ISCM.Domain.Enums;

/// <summary>
/// Classification of verification path independence.
/// 
/// Phase 8 — Verification Architecture
/// 
/// Contract (from Final Engineering Specification, Section 2.2):
///   - "PowerShell / Registry / WMI" are technology mechanisms, not automatically independent.
///   - Independence must be evaluated based on:
///       source, acquisition mechanism, underlying authoritative state,
///       failure mode, implementation dependency.
///   - A path must not be labelled "Independent" unless its independence
///     is technically defensible.
/// 
/// Precedence (weakest → strongest):
///   Duplicate        → same evidence source, same result, no value
///   SharedSource     → different API but same underlying state
///   PartialIndependent → different acquisition, partially correlated
///   Independent      → different authoritative state source
/// </summary>
public enum IndependenceClass
{
    /// <summary>
    /// Path is not declared / not implemented.
    /// Used as default sentinel when no class has been assigned.
    /// </summary>
    Undeclared = 0,

    /// <summary>
    /// Path produces the same evidence as another path
    /// (duplicate execution, wrapper, or copy).
    /// Must not be counted toward required path count.
    /// </summary>
    Duplicate = 1,

    /// <summary>
    /// Path uses a different API/mechanism but reads the
    /// same underlying authoritative state as another path
    /// (e.g., Registry API + PowerShell Get-ItemProperty on the same key).
    /// Counts toward path count with reduced confidence.
    /// </summary>
    SharedSource = 2,

    /// <summary>
    /// Path uses a different acquisition mechanism and
    /// different authoritative state source, but may still
    /// share failure modes with other paths
    /// (e.g., secedit + net accounts for security policy).
    /// </summary>
    PartiallyIndependent = 3,

    /// <summary>
    /// Path uses a genuinely independent authoritative source,
    /// different acquisition mechanism, and different failure mode
    /// (e.g., Registry vs Event Log vs Audit trail).
    /// Full confidence in independent verification.
    /// </summary>
    Independent = 4
}