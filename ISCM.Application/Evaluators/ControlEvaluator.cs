using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Evaluators;

/// <summary>
/// Default implementation of IControlEvaluator.
/// Applies deterministic aggregation rules to produce Parent Status.
/// </summary>
public class ControlEvaluator : IControlEvaluator
{
    public ControlResult Evaluate(
        ControlDefinition controlDefinition,
        IEnumerable<SubControlResult> subControlResults)
    {
        var results = subControlResults?.ToList() ?? new List<SubControlResult>();

        var controlResult = new ControlResult
        {
            ControlId = controlDefinition?.ControlId ?? "Unknown",
            EvaluatedAt = DateTime.UtcNow
        };

        // Rule 1: No results → UNKNOWN
        if (!results.Any())
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        // Add all SubControlResults to the ControlResult
        controlResult.SubControlResults = results;

        // Filter out N/A SubControls (not applicable to this OS/build)
        var applicableResults = results
            .Where(r => r.Status != CheckStatus.NotApplicable)
            .ToList();

        // Rule 2: No applicable results → N/A
        if (!applicableResults.Any())
        {
            controlResult.Status = CheckStatus.NotApplicable;
            return controlResult;
        }

        // Rule 3: Any ERROR → ERROR (evaluation crashed)
        if (applicableResults.Any(r => r.Status == CheckStatus.Error))
        {
            controlResult.Status = CheckStatus.Error;
            return controlResult;
        }

        // Rule 4: Any FAIL (required) → FAIL
        var requiredFailures = applicableResults
            .Where(r => r.Status == CheckStatus.Fail)
            .ToList();

        if (requiredFailures.Any())
        {
            controlResult.Status = CheckStatus.Fail;
            return controlResult;
        }

        // Rule 5: Any UNKNOWN (required) → UNKNOWN
        var unknowns = applicableResults
            .Where(r => r.Status == CheckStatus.Unknown)
            .ToList();

        if (unknowns.Any())
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        // Rule 6: All PASS → PASS
        if (applicableResults.All(r => r.Status == CheckStatus.Pass))
        {
            controlResult.Status = CheckStatus.Pass;
            return controlResult;
        }

        // Fallback: UNKNOWN (should not reach here)
        controlResult.Status = CheckStatus.Unknown;
        return controlResult;
    }

    /// <summary>
    /// Temporary implementation for migration phase.
    /// Converts Findings to SubControlResults and delegates to Evaluate().
    /// </summary>
    public ControlResult EvaluateFromFindings(
        ControlDefinition controlDefinition,
        IEnumerable<Finding> findings)
    {
        var findingsList = findings?.ToList() ?? new List<Finding>();

        // Convert Findings to SubControlResults (temporary mapping)
        var subControlResults = findingsList.Select(f => new SubControlResult
        {
            SubControlId = f.CheckId, // Using CheckId as temporary SubControlId
            Status = f.Status,
            Evidence = new List<Evidence>
            {
                new Evidence
                {
                    SourceType = f.SourceType,
                    SourceName = f.SourceCommand,
                    RawOutput = f.CurrentValue,
                    ExpectedValue = f.ExpectedValue,
                    Evaluation = f.Status,
                    Timestamp = DateTime.UtcNow
                }
            },
            EvaluatedAt = DateTime.UtcNow
        }).ToList();

        return Evaluate(controlDefinition, subControlResults);
    }
}