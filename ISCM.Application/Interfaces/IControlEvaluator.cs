using System.Collections.Generic;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Responsible for aggregating SubControlResults into a ControlResult.
/// This interface enforces the separation between definition (ControlDefinition)
/// and runtime evaluation (ControlResult).
/// </summary>
public interface IControlEvaluator
{
    /// <summary>
    /// Calculates the parent ControlResult based on its SubControlResults.
    /// 
    /// Aggregation Rules:
    /// - If no SubControlResults → UNKNOWN
    /// - If any SubControlResult is ERROR → ERROR
    /// - If any required SubControlResult is FAIL → FAIL
    /// - If any required SubControlResult is UNKNOWN → UNKNOWN
    /// - If all required SubControlResults are PASS → PASS
    /// - N/A SubControls are excluded from aggregation
    /// - Ignored/FalsePositive are governance states, not evaluation states
    /// </summary>
    /// <param name="controlDefinition">The parent control definition</param>
    /// <param name="subControlResults">List of evaluated SubControlResults</param>
    /// <returns>Aggregated ControlResult</returns>
    ControlResult Evaluate(
        ControlDefinition controlDefinition,
        IEnumerable<SubControlResult> subControlResults);

    /// <summary>
    /// Temporary overload for migration phase.
    /// Calculates ControlResult from Finding objects (legacy model).
    /// Will be deprecated once all checks produce SubControlResults.
    /// </summary>
    ControlResult EvaluateFromFindings(
        ControlDefinition controlDefinition,
        IEnumerable<Finding> findings);
}