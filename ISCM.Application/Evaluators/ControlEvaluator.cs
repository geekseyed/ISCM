using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Evaluators;

public class ControlEvaluator : IControlEvaluator
{
    public ControlResult Evaluate(ControlDefinition controlDefinition, IEnumerable<SubControlResult> subControlResults)
    {
        var results = subControlResults?.ToList() ?? new List<SubControlResult>();

        var controlResult = new ControlResult
        {
            ControlId = controlDefinition?.ControlId ?? "Unknown",
            EvaluatedAt = DateTime.UtcNow
        };

        if (results.Count == 0)
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        controlResult.SubControlResults = results;

        var applicable = results.Where(r => r.Status != CheckStatus.NotApplicable).ToList();

        if (applicable.Count == 0)
        {
            controlResult.Status = CheckStatus.NotApplicable;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Error))
        {
            controlResult.Status = CheckStatus.Error;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Fail))
        {
            controlResult.Status = CheckStatus.Fail;
            return controlResult;
        }

        if (applicable.Any(r => r.Status == CheckStatus.Unknown))
        {
            controlResult.Status = CheckStatus.Unknown;
            return controlResult;
        }

        if (applicable.All(r => r.Status == CheckStatus.Pass))
        {
            controlResult.Status = CheckStatus.Pass;
            return controlResult;
        }

        controlResult.Status = CheckStatus.Unknown;
        return controlResult;
    }

    public Finding EvaluateFromSubControls(ControlDefinition controlDefinition, List<SubControlResult> subControlResults, string? checkId = null)
    {
        var controlResult = Evaluate(controlDefinition, subControlResults);
        var allEvidence = subControlResults.SelectMany(s => s.EvidenceItems).ToList();

        var primaryCheckId = checkId
            ?? controlDefinition.TechnicalCheckIds.FirstOrDefault()
            ?? controlDefinition.ControlId;

        var finding = new Finding(
            checkId: primaryCheckId,
            name: controlDefinition.Title,
            category: controlDefinition.Category,
            severity: controlDefinition.Severity,
            status: controlResult.Status,
            currentValue: allEvidence.FirstOrDefault()?.RawOutput ?? "No evidence collected",
            expectedValue: subControlResults.FirstOrDefault()?.EvidenceItems.FirstOrDefault()?.ExpectedValue ?? "N/A",
            description: controlDefinition.Description,
            errorMessage: null,
            registryPath: string.Empty,
            cisReference: controlDefinition.BaselineId,
            riskScore: (int)controlDefinition.Severity * 20,
            sourceType: "Multi-Source Evidence",
            sourceCommand: string.Join(", ", allEvidence.Select(e => e.SourceName).Distinct()),
            fixTools: new List<string>(),
            subChecks: null,
            recommendation: $"Review and harden: {controlDefinition.Title}"
        );

        foreach (var evidence in allEvidence)
        {
            finding.AddTestResult(new TestResult(
                evidence.SourceType.ToString(), // ✅ اصلاح: تبدیل Enum به string
                evidence.SourceName,
                evidence.Evaluation == CheckStatus.Pass,
                evidence.RawOutput
            ));
        }

        return finding;
    }

    public ControlResult EvaluateFromFindings(ControlDefinition controlDefinition, IEnumerable<Finding> findings)
    {
        var findingsList = findings?.ToList() ?? new List<Finding>();

        var subControlResults = findingsList.Select(f =>
        {
            Enum.TryParse<EvidenceSourceType>(f.SourceType, true, out var parsedSourceType); // ✅ اصلاح: تبدیل امن string به Enum

            return new SubControlResult
            {
                SubControlId = f.CheckId,
                Status = f.Status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Unknown,
                        SourceName = f.SourceCommand,
                        RawOutput = f.CurrentValue,
                        ExpectedValue = f.ExpectedValue,
                        Evaluation = f.Status,
                        CollectedAtUtc = DateTime.UtcNow // ✅ اصلاح: تغییر نام فیلد
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }).ToList();

        return Evaluate(controlDefinition, subControlResults);
    }
}