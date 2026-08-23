using System;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents a single, auditable piece of evidence collected during a scan.
/// </summary>
public class Evidence
{
    public string SourceType { get; set; } = string.Empty; // e.g., Registry, PowerShell, WMI, SecEdit
    public string SourceName { get; set; } = string.Empty; // e.g., HKLM\...\MinPasswordLen
    public string Command { get; set; } = string.Empty;    // Exact command or API call executed
    public string RawOutput { get; set; } = string.Empty;  // Unmodified raw data (for audit)
    public string ParsedValue { get; set; } = string.Empty; // Structured value extracted by Parser
    public string ExpectedValue { get; set; } = string.Empty;
    public CheckStatus Evaluation { get; set; }
    public string EvaluationReason { get; set; } = string.Empty; // Why this status was chosen
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? Error { get; set; } // Populated if collection or parsing failed
}