using System.Collections.Generic;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents the definition of a single, independently evaluable security setting (SubControl).
/// This is immutable metadata that defines WHAT to check, not the result.
/// </summary>
public class SubControlDefinition
{
    /// <summary>
    /// Unique identifier for this sub-control (e.g., "PWD-001.1", "PWD-001.2")
    /// </summary>
    public string SubControlId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable name of the setting (e.g., "Enforce password history")
    /// </summary>
    public string SettingName { get; set; } = string.Empty;

    /// <summary>
    /// Description of what this setting does
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// The expected compliant value (e.g., "24 passwords remembered", "14 characters", "Enabled")
    /// </summary>
    public string ExpectedValue { get; set; } = string.Empty;

    /// <summary>
    /// List of evidence sources that can be used to evaluate this setting
    /// (e.g., "net accounts", "secedit", "Registry HKLM\...\MinPasswordLen")
    /// </summary>
    public List<string> EvidenceSources { get; set; } = new();

    /// <summary>
    /// The category of this sub-control (inherited from parent or specific)
    /// </summary>
    public CheckCategory Category { get; set; }

    /// <summary>
    /// The severity of this sub-control (inherited from parent or specific)
    /// </summary>
    public CheckSeverity Severity { get; set; }

    /// <summary>
    /// Applicability rules (e.g., "Windows 11 22H2+", "Requires Pro/Enterprise")
    /// </summary>
    public string? ApplicabilityRule { get; set; }

    /// <summary>
    /// Whether this sub-control is required for the parent to be considered compliant
    /// </summary>
    public bool IsRequired { get; set; } = true;

    /// <summary>
    /// Reference to the parent control
    /// </summary>
    public string ParentControlId { get; set; } = string.Empty;
}