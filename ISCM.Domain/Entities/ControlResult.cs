using System;
using System.Collections.Generic;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents the aggregated runtime result of a Parent Control after evaluating all its SubControls.
/// </summary>
public class ControlResult
{
    public string ControlId { get; set; } = string.Empty;
    public CheckStatus Status { get; set; }
    public List<SubControlResult> SubControlResults { get; set; } = new();
    public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;
}