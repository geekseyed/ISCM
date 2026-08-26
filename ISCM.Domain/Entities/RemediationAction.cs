using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents a remediation action that can fix a failed security control.
/// </summary>
public class RemediationAction : BaseEntity
{
    /// <summary>
    /// Unique identifier for the remediation action
    /// </summary>
    public string RemediationId { get; set; } = string.Empty;

    /// <summary>
    /// The CheckId this remediation applies to
    /// </summary>
    public string CheckId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable title of the remediation
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of what the remediation does
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Type of remediation (Registry, PowerShell, Script, Config)
    /// </summary>
    public RemediationType Type { get; set; }

    /// <summary>
    /// The actual script or command to execute
    /// </summary>
    public string Script { get; set; } = string.Empty;

    /// <summary>
    /// Risk level of executing this remediation
    /// </summary>
    public CheckSeverity RiskLevel { get; set; }

    /// <summary>
    /// Whether a reboot is required after remediation
    /// </summary>
    public bool RequiresReboot { get; set; }

    /// <summary>
    /// Estimated time to complete (in seconds)
    /// </summary>
    public int EstimatedDurationSeconds { get; set; }

    /// <summary>
    /// Prerequisites that must be met before remediation
    /// </summary>
    public List<string> Prerequisites { get; set; } = new();

    /// <summary>
    /// Side effects or warnings to inform the user about
    /// </summary>
    public List<string> Warnings { get; set; } = new();

    /// <summary>
    /// Whether this remediation is currently active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Collection of remediation history for this action
    /// </summary>
    public List<RemediationHistory> ExecutionHistory { get; set; } = new();
}