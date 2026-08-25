using ISCM.Domain.Common;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents a security baseline standard (e.g., Hosseini, ERDC, CIS).
/// A baseline is a collection of security controls that must be evaluated.
/// </summary>
public class BaselineDefinition : BaseEntity
{
    /// <summary>
    /// Unique identifier for the baseline (e.g., "HOSSEINI-V1", "ERDC-V1")
    /// </summary>
    public string BaselineId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable name (e.g., "Hosseini Windows 11 Hardening Standard")
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Version of the baseline (e.g., "1.0", "2.1")
    /// </summary>
    public string Version { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of the baseline
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether this is the default baseline for new scans
    /// </summary>
    public bool IsDefault { get; set; }

    /// <summary>
    /// Whether this baseline is currently active
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Reference document path or URL
    /// </summary>
    public string? ReferenceDocument { get; set; }

    /// <summary>
    /// Collection of controls mapped to this baseline
    /// </summary>
    public List<BaselineControlMapping> ControlMappings { get; set; } = new();

    /// <summary>
    /// Collection of scans that used this baseline
    /// </summary>
    public List<ScanResult> ScanResults { get; set; } = new();
}