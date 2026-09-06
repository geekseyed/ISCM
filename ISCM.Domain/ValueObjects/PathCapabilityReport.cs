using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Report describing the path capability of a SubControl.
/// 
/// Phase 8.3 — Sub-Phase 8.3.2
/// 
/// Moved from Application.Services to Domain.ValueObjects
/// so it can be referenced by SubControlResult (Domain layer)
/// without creating circular dependencies.
/// </summary>
public class PathCapabilityReport
{
    public string SubControlId { get; set; } = string.Empty;

    public int RequiredPathCount { get; set; }

    public IndependenceClass RequiredIndependenceClass { get; set; } = IndependenceClass.Undeclared;

    public int DeclaredPathCount { get; set; }

    public int AvailablePathCount { get; set; }

    public int CountedPathCount { get; set; }

    public int IndependentPathCount { get; set; }

    public bool MeetsPathCountRequirement { get; set; }

    public bool MeetsIndependenceRequirement { get; set; }

    public bool IsValid { get; set; }

    public List<string> Errors { get; set; } = new();

    public List<string> Warnings { get; set; } = new();

    public DateTime EvaluatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Overall capability status.
    /// </summary>
    public PathCapabilityStatus Status
    {
        get
        {
            if (!IsValid || Errors.Count > 0)
                return PathCapabilityStatus.Invalid;

            if (!MeetsPathCountRequirement)
                return PathCapabilityStatus.InsufficientPaths;

            if (!MeetsIndependenceRequirement)
                return PathCapabilityStatus.InsufficientIndependence;

            return PathCapabilityStatus.Satisfied;
        }
    }

    public override string ToString()
        => $"[SubControl={SubControlId}, Status={Status}, Counted={CountedPathCount}/{RequiredPathCount}, Independence={MeetsIndependenceRequirement}]";
}

/// <summary>
/// Overall status of path capability for a SubControl.
/// </summary>
public enum PathCapabilityStatus
{
    /// <summary>Path capability is satisfied (all requirements met).</summary>
    Satisfied = 0,

    /// <summary>Path configuration is invalid (errors present).</summary>
    Invalid = 1,

    /// <summary>Not enough counted paths to meet RequiredPathCount.</summary>
    InsufficientPaths = 2,

    /// <summary>Counted paths do not meet RequiredIndependenceClass.</summary>
    InsufficientIndependence = 3
}