using ISCM.Domain.Common;

namespace ISCM.Domain.Entities;

/// <summary>
/// Maps a control to a baseline with specific requirements.
/// Defines which controls belong to which baseline and their expected states.
/// </summary>
public class BaselineControlMapping : BaseEntity
{
    /// <summary>
    /// Baseline this mapping belongs to
    /// </summary>
    public string BaselineId { get; set; } = string.Empty;
    public BaselineDefinition? Baseline { get; set; }

    /// <summary>
    /// Control ID from ControlCatalog (e.g., "01", "10", "EXT-01")
    /// </summary>
    public string ControlId { get; set; } = string.Empty;

    /// <summary>
    /// Whether this control is required in the baseline
    /// </summary>
    public bool IsRequired { get; set; } = true;

    /// <summary>
    /// Expected override value (if different from default control expectation)
    /// </summary>
    public string? ExpectedOverride { get; set; }

    /// <summary>
    /// Priority level (1=Critical, 2=High, 3=Medium, 4=Low)
    /// </summary>
    public int Priority { get; set; } = 2;

    /// <summary>
    /// Whether this mapping is currently active
    /// </summary>
    public bool IsActive { get; set; } = true;
}