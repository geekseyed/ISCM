namespace ISCM.Domain.Enums;

/// <summary>
/// Classification of agreement state across verification paths.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.1
/// 
/// Contract (from Final Engineering Specification, Section 9.1):
///   - Deterministic matrix: every combination produces a defined state
///   - Never: disagreement → PASS
///   - Never: unavailable path → silently ignored
///   - Never: path result → overwritten by consensus
/// 
/// States (from weakest to strongest evidence):
///   IncompleteVerification → some paths failed to execute (Error/Unknown)
///   Disagreement          → paths disagree (PASS/FAIL mix, never PASS)
///   UnanimousFailure      → all paths agree on FAIL
///   MajorityAgreement     → most paths agree (rare, typically with 4+ paths)
///   FullAgreement         → all paths agree (typically on PASS)
/// </summary>
public enum AgreementState
{
    /// <summary>
    /// One or more paths failed to execute (Error or Unknown status).
    /// Verification is incomplete; cannot produce reliable verdict.
    /// </summary>
    IncompleteVerification = 0,

    /// <summary>
    /// Paths produced conflicting results (e.g., PASS/FAIL mix).
    /// Never automatically resolved to PASS.
    /// Requires human review or additional investigation.
    /// </summary>
    Disagreement = 1,

    /// <summary>
    /// All paths agree on FAIL.
    /// Strong evidence of non-compliance.
    /// </summary>
    UnanimousFailure = 2,

    /// <summary>
    /// Majority of paths agree (typically used when 4+ paths exist).
    /// For 3-path systems, this is rarely used; prefer FullAgreement or Disagreement.
    /// </summary>
    MajorityAgreement = 3,

    /// <summary>
    /// All paths agree (typically on PASS).
    /// Strong evidence of compliance.
    /// </summary>
    FullAgreement = 4
}