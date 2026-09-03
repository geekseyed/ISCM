using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Application.Interfaces;

public interface IHardeningCheck
{
    string CheckId { get; }
    string Name { get; }
    CheckCategory Category { get; }
    CheckSeverity Severity { get; }

    /// <summary>
    /// Evaluates the check and returns a single Finding (legacy method).
    /// </summary>
    Task<Finding> EvaluateAsync();

    /// <summary>
    /// Phase 2.5: Evaluates all SubControls independently and returns detailed results with Evidence.
    /// Default implementation wraps EvaluateAsync() result. Concrete checks can override for detailed evaluation.
    /// </summary>
    async Task<List<SubControlResult>> EvaluateSubControlsAsync()
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
                    SourceType = parsedSourceType != EvidenceSourceType.Unknown ? parsedSourceType : EvidenceSourceType.Unknown,
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