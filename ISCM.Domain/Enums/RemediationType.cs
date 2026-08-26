namespace ISCM.Domain.Enums;

/// <summary>
/// Types of remediation actions.
/// </summary>
public enum RemediationType
{
    /// <summary>
    /// Registry value modification
    /// </summary>
    Registry = 0,

    /// <summary>
    /// PowerShell script execution
    /// </summary>
    PowerShell = 1,

    /// <summary>
    /// Batch script execution
    /// </summary>
    BatchScript = 2,

    /// <summary>
    /// Configuration file modification
    /// </summary>
    ConfigFile = 3,

    /// <summary>
    /// Windows Feature enable/disable
    /// </summary>
    WindowsFeature = 4,

    /// <summary>
    /// Group Policy modification
    /// </summary>
    GroupPolicy = 5,

    /// <summary>
    /// Service start/stop/configuration
    /// </summary>
    Service = 6
}