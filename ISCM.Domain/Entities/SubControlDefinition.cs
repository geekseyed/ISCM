using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class SubControlDefinition
{
    public string SubControlId { get; set; }
    public string SettingName { get; set; }
    public string Description { get; set; }
    public string ExpectedValue { get; set; }
    public List<string> EvidenceSources { get; set; }
    public CheckCategory Category { get; set; }
    public CheckSeverity Severity { get; set; }
    public string? ApplicabilityRule { get; set; }
    public bool IsRequired { get; set; }
    public string ParentControlId { get; set; }
    public ValueType ValueType { get; set; }
    public Operator Operator { get; set; }
}