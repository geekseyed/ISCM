using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class PathResult
{
    public string PathId { get; set; }
    public CheckStatus Status { get; set; }
    public string? EvidenceId { get; set; }
    public string EvaluationDetail { get; set; }
    public string? DiagnosticInfo { get; set; }
    public DateTime ExecutedAt { get; set; }
}