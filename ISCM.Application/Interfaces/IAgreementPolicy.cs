using ISCM.Domain.Entities;
using ISCM.Domain.ValueObjects;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Contract for agreement/disagreement policy implementations.
/// 
/// Phase 9 — Agreement / Disagreement Engine, Sub-Phase 9.1
/// 
/// Responsibilities:
///   1. Analyze a list of PathResult objects
///   2. Apply deterministic agreement logic
///   3. Produce an AgreementDecision with SelectedVerdict and AgreementState
/// 
/// Contract rules (from Final Engineering Specification, Section 9.2):
///   - NEVER: disagreement → PASS
///   - NEVER: unavailable path → silently ignored
///   - NEVER: path result → overwritten by consensus without preservation
///   - All path results must be preserved in AgreementDecision.PathContributions
/// 
/// Implementations:
///   - DefaultAgreementPolicy (Phase 9.2): deterministic matrix for 3-path systems
///   - Future: weighted policies, confidence-based policies, etc.
/// </summary>
public interface IAgreementPolicy
{
    /// <summary>
    /// Analyzes path results and produces an agreement decision.
    /// </summary>
    /// <param name="pathResults">
    /// List of PathResult objects from verification paths.
    /// Must not be null, but can be empty.
    /// </param>
    /// <returns>
    /// AgreementDecision with:
    ///   - SelectedVerdict: the final CheckStatus
    ///   - AgreementState: classification of agreement
    ///   - Reason: human-readable explanation
    ///   - PathContributions: breakdown per path (preserved for audit)
    /// </returns>
    AgreementDecision Decide(IReadOnlyList<PathResult> pathResults);

    /// <summary>
    /// Name of this policy for diagnostics and logging.
    /// </summary>
    string PolicyName { get; }

    /// <summary>
    /// Description of this policy's behavior.
    /// </summary>
    string PolicyDescription { get; }
}