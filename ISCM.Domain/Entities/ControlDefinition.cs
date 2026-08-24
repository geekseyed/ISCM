using System.Collections.Generic;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Immutable definition of a Parent Control. 
/// Contains ONLY metadata and mapping. NO runtime calculation logic.
/// </summary>
public class ControlDefinition
{
    public string ControlId { get; set; } = string.Empty;
    public string BaselineId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public CheckCategory Category { get; set; }
    public CheckSeverity Severity { get; set; }
    public bool IsBaseline { get; set; } = true;
    public List<string> TechnicalCheckIds { get; set; } = new();

    /// <summary>
    /// List of SubControl definitions that belong to this parent control.
    /// Each SubControl represents an independently evaluable setting.
    /// </summary>
    public List<SubControlDefinition> SubControls { get; set; } = new();

    // NOTE: CalculateParentStatus() has been REMOVED from here.
    // Aggregation logic now belongs exclusively to IControlEvaluator in the Application Layer.
}