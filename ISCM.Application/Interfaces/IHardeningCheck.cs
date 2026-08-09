using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IHardeningCheck
{
    string CheckId { get; }
    string Name { get; }
    CheckCategory Category { get; }
    CheckSeverity Severity { get; }
    Task<Finding> EvaluateAsync();
}