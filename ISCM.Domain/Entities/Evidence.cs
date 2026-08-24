using System;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities
{
    /// <summary>
    /// Represents a single, auditable piece of evidence collected during a scan.
    /// This is the core of the "Proof" in Security Compliance.
    /// </summary>
    public class Evidence
    {
        public string EvidenceId { get; set; } = Guid.NewGuid().ToString();
        public string SourceType { get; set; } = string.Empty;
        public string SourceName { get; set; } = string.Empty;
        public string Command { get; set; } = string.Empty;
        public string RawOutput { get; set; } = string.Empty;
        public string ParsedValue { get; set; } = string.Empty;
        public string ExpectedValue { get; set; } = string.Empty;
        public CheckStatus Evaluation { get; set; }
        public string EvaluationReason { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int DurationMs { get; set; }
        public string? Error { get; set; }
    }
}