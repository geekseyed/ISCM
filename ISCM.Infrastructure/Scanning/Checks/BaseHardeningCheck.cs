using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

public abstract class BaseHardeningCheck : IHardeningCheck
{
    public abstract string CheckId { get; }
    public abstract string Name { get; }
    public abstract CheckCategory Category { get; }
    public abstract CheckSeverity Severity { get; }

    public abstract Task<Finding> EvaluateAsync();

    public virtual async Task<List<SubControlResult>> EvaluateSubControlsAsync()
    {
        var finding = await EvaluateAsync();

        Enum.TryParse<EvidenceSourceType>(finding.SourceType, true, out var parsedSourceType);

        var subControlResult = new SubControlResult
        {
            SubControlId = CheckId,
            Status = finding.Status,
            EvidenceItems = new List<Evidence>
            {
                new Evidence
                {
                    SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Other,
                    SourceName = finding.SourceCommand,
                    RawOutput = finding.CurrentValue,
                    ExpectedValue = finding.ExpectedValue,
                    Evaluation = finding.Status,
                    EvaluationReason = finding.Description,
                    CollectedAtUtc = DateTime.UtcNow
                }
            },
            EvaluatedAt = DateTime.UtcNow
        };

        return new List<SubControlResult> { subControlResult };
    }
}