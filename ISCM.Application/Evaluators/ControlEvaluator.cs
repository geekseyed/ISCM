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

    public Finding EvaluateFromSubControls(ControlDefinition controlDefinition, List<SubControlResult> subControlResults)
    {
        var controlResult = Evaluate(controlDefinition, subControlResults);
        var allEvidence = subControlResults.SelectMany(s => s.EvidenceItems).ToList();

        // استفاده از اولین TechnicalCheckId
        var primaryCheckId = controlDefinition.TechnicalCheckIds.FirstOrDefault() ?? controlDefinition.ControlId;

        // DEBUG LOG
        Console.WriteLine($"[DEBUG] EvaluateFromSubControls:");
        Console.WriteLine($"  - ControlId: {controlDefinition.ControlId}");
        Console.WriteLine($"  - Title: {controlDefinition.Title}");
        Console.WriteLine($"  - TechnicalCheckIds: {string.Join(", ", controlDefinition.TechnicalCheckIds)}");
        Console.WriteLine($"  - PrimaryCheckId (for Finding): {primaryCheckId}");
        Console.WriteLine($"  - SubControlResults count: {subControlResults.Count}");

        var finding = new Finding(
            primaryCheckId,
            controlDefinition.Title,
            controlDefinition.Category,
            controlDefinition.Severity,
            controlResult.Status,
            allEvidence.FirstOrDefault()?.RawOutput ?? "No evidence collected",
            subControlResults.FirstOrDefault()?.EvidenceItems.FirstOrDefault()?.ExpectedValue ?? "N/A",
            controlDefinition.Description,
            errorMessage: null,
            description: controlDefinition.Description,
            registryPath: string.Empty,
            cisReference: controlDefinition.BaselineId,
            riskScore: (int)controlDefinition.Severity * 20,
            sourceType: "Multi-Source Evidence",
            sourceCommand: string.Join(", ", allEvidence.Select(e => e.SourceName).Distinct()),
            fixTools: new List<string>()
        );

        Console.WriteLine($"  - Finding.CheckId: {finding.CheckId}");
        Console.WriteLine($"  - Finding.Status: {finding.Status}");

        foreach (var evidence in allEvidence)
        {
            finding.AddTestResult(new TestResult(
                evidence.SourceType,
                evidence.SourceName,
                evidence.Evaluation == CheckStatus.Pass,
                evidence.RawOutput
            ));
        }

        return finding;
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