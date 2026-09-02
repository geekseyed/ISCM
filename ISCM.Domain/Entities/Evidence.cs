using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class Evidence
{
    public string EvidenceId { get; set; }
    public string? ScanId { get; set; }
    public string? SubControlId { get; set; }
    public string? PathId { get; set; }
    public string SourceType { get; set; }
    public string SourceName { get; set; }
    public string Command { get; set; }
    public string RawOutput { get; set; }
    public string ParsedValue { get; set; }
    public string ExpectedValue { get; set; }
    public CheckStatus Evaluation { get; set; }
    public string EvaluationReason { get; set; }
    public DateTime Timestamp { get; set; }
    public int DurationMs { get; set; }
    public string? Error { get; set; }
    public string? Fingerprint { get; set; }
}