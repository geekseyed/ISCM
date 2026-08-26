using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Tracks the execution history of a remediation action.
/// </summary>
public class RemediationHistory : BaseEntity
{
    /// <summary>
    /// Reference to the remediation action
    /// </summary>
    public string RemediationId { get; set; } = string.Empty;
    public RemediationAction? Remediation { get; set; }

    /// <summary>
    /// The ScanResult this remediation was applied to
    /// </summary>
    public string? ScanResultId { get; set; }
    public ScanResult? ScanResult { get; set; }

    /// <summary>
    /// When the remediation was executed
    /// </summary>
    public DateTimeOffset ExecutedAt { get; set; }

    /// <summary>
    /// Who executed the remediation (username)
    /// </summary>
    public string? ExecutedBy { get; set; }

    /// <summary>
    /// Result of the remediation execution
    /// </summary>
    public RemediationStatus Status { get; set; }

    /// <summary>
    /// Output or error message from execution
    /// </summary>
    public string? ExecutionOutput { get; set; }

    /// <summary>
    /// Backup of the original value (for rollback)
    /// </summary>
    public string? BackupValue { get; set; }

    /// <summary>
    /// Whether rollback is available
    /// </summary>
    public bool CanRollback { get; set; }

    /// <summary>
    /// When rollback was performed (if applicable)
    /// </summary>
    public DateTimeOffset? RolledBackAt { get; set; }

    /// <summary>
    /// Who performed the rollback
    /// </summary>
    public string? RolledBackBy { get; set; }
}