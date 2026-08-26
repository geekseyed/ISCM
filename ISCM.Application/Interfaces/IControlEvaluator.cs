using ISCM.Domain.Entities;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Evaluates SubControl results into control-level results and findings.
/// </summary>
public interface IControlEvaluator
{
    /// <summary>
    /// Aggregates SubControl results into a single ControlResult.
    /// </summary>
    ControlResult Evaluate(ControlDefinition controlDefinition, IEnumerable<SubControlResult> subControlResults);

    /// <summary>
    /// Builds a Finding from SubControl results.
    /// If checkId is provided, it is used as the Finding's CheckId so that
    /// multiple checks of the same control (UAC/LM/ADM) don't overwrite each other.
    /// </summary>
    Finding EvaluateFromSubControls(ControlDefinition controlDefinition, List<SubControlResult> subControlResults, string? checkId = null);

    /// <summary>
    /// Evaluates a control from existing findings (used by the Findings UI).
    /// </summary>
    ControlResult EvaluateFromFindings(ControlDefinition controlDefinition, IEnumerable<Finding> findings);
}