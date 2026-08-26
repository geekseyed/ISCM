namespace ISCM.Domain.Enums;

/// <summary>
/// Status of a remediation execution.
/// </summary>
public enum RemediationStatus
{
    /// <summary>
    /// Remediation is pending execution
    /// </summary>
    Pending = 0,

    /// <summary>
    /// Remediation is currently executing
    /// </summary>
    Executing = 1,

    /// <summary>
    /// Remediation completed successfully
    /// </summary>
    Success = 2,

    /// <summary>
    /// Remediation failed
    /// </summary>
    Failed = 3,

    /// <summary>
    /// Remediation was rolled back
    /// </summary>
    RolledBack = 4,

    /// <summary>
    /// Remediation was cancelled
    /// </summary>
    Cancelled = 5
}