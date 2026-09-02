using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class SubControlDefinition
{
    public string SubControlId { get; set; }
    public string SettingName { get; set; }
    public string Description { get; set; }
    public string ExpectedValue { get; set; }
    public List<string> EvidenceSources { get; set; } = new();
    public CheckCategory Category { get; set; }
    public CheckSeverity Severity { get; set; }
    public string? ApplicabilityRule { get; set; }
    public bool IsRequired { get; set; }
    public string ParentControlId { get; set; }
    public ExpectedValueType ExpectedValueType { get; set; }
    public Operator Operator { get; set; }
    public int RequiredPathCount { get; set; } = 1;
    public List<string> RemediationIds { get; set; } = new();
}