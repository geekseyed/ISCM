using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Base class for all hardening checks. Provides default implementation for EvaluateSubControlsAsync.
/// </summary>
public abstract class BaseHardeningCheck : IHardeningCheck
{
    public abstract string CheckId { get; }
    public abstract string Name { get; }
    public abstract CheckCategory Category { get; }
    public abstract CheckSeverity Severity { get; }

    public abstract Task<Finding> EvaluateAsync();

    /// <summary>
    /// Default implementation: delegates to EvaluateAsync and wraps result in a single SubControlResult.
    /// Override this in concrete checks to provide detailed SubControl evaluation.
    /// </summary>
    public virtual async Task<List<SubControlResult>> EvaluateSubControlsAsync()
    {
        var finding = await EvaluateAsync();

        var subControlResult = new SubControlResult
        {
            SubControlId = CheckId,
            Status = finding.Status,
            EvidenceItems = new List<Evidence>
            {
                new Evidence
                {
                    SourceType = finding.SourceType,
                    SourceName = finding.SourceCommand,
                    RawOutput = finding.CurrentValue,
                    ExpectedValue = finding.ExpectedValue,
                    Evaluation = finding.Status,
                    EvaluationReason = finding.Description,
                    Timestamp = System.DateTime.UtcNow
                }
            },
            EvaluatedAt = System.DateTime.UtcNow
        };

        return new List<SubControlResult> { subControlResult };
    }
}