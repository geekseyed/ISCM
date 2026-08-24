using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Evaluators;

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

        if (!results.Any())
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        controlResult.SubControlResults = results;

        var applicableResults = results
            .Where(r => r.Status != CheckStatus.NotApplicable)
            .ToList();

        if (!applicableResults.Any())
        {
            controlResult.Status = CheckStatus.NotApplicable;
            return controlResult;
        }

        if (applicableResults.Any(r => r.Status == CheckStatus.Error))
        {
            controlResult.Status = CheckStatus.Error;
            return controlResult;
        }

        var requiredFailures = applicableResults
            .Where(r => r.Status == CheckStatus.Fail)
            .ToList();

        if (requiredFailures.Any())
        {
            controlResult.Status = CheckStatus.Fail;
            return controlResult;
        }

        var unknowns = applicableResults
            .Where(r => r.Status == CheckStatus.Unknown)
            .ToList();

        if (unknowns.Any())
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        if (applicableResults.All(r => r.Status == CheckStatus.Pass))
        {
            controlResult.Status = CheckStatus.Pass;
            return controlResult;
        }

        controlResult.Status = CheckStatus.Unknown;
        return controlResult;
    }

    public ControlResult EvaluateFromFindings(
        ControlDefinition controlDefinition,
        IEnumerable<Finding> findings)
    {
        var findingsList = findings?.ToList() ?? new List<Finding>();

        var subControlResults = findingsList.Select(f => new SubControlResult
        {
            SubControlId = f.CheckId,
            Status = f.Status,
            EvidenceItems = new List<Evidence> 
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