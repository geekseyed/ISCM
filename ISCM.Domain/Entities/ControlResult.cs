using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class ControlResult
{
    public string ControlId { get; set; }
    public string ParentControlId { get; set; }
    public CheckStatus Status { get; set; }
    public List<SubControlResult> SubControlResults { get; set; } = new();
    public DateTime EvaluatedAt { get; set; }
}