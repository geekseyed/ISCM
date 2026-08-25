using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

public interface IControlEvaluator
{
    /// <summary>
    /// Evaluates a list of SubControlResults and returns an aggregated ControlResult.
    /// </summary>
    ControlResult Evaluate(
        ControlDefinition controlDefinition,
        IEnumerable<SubControlResult> subControlResults);

    /// <summary>
    /// Phase 2.5: Evaluates SubControlResults and returns a Finding with all evidence.
    /// </summary>
    Finding EvaluateFromSubControls(
        ControlDefinition controlDefinition,
        List<SubControlResult> subControlResults);

    /// <summary>
    /// Legacy method: converts Findings to SubControlResults and evaluates.
    /// </summary>
    ControlResult EvaluateFromFindings(
        ControlDefinition controlDefinition,
        IEnumerable<Finding> findings);
}