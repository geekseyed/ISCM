using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class SubControlResult
{
    public string SubControlId { get; set; }
    public CheckStatus Status { get; set; }
    public List<Evidence> EvidenceItems { get; set; } = new();
    public List<string> EvidenceReferences { get; set; } = new();
    public List<PathResult> VerificationResults { get; set; } = new();
    public DateTime EvaluatedAt { get; set; }
}