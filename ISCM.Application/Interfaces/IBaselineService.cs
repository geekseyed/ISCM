using ISCM.Domain.Entities;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Service for managing security baselines.
/// </summary>
public interface IBaselineService
{
    /// <summary>
    /// Gets all available baselines.
    /// </summary>
    List<BaselineDefinition> GetAllBaselines();

    /// <summary>
    /// Gets the default baseline.
    /// </summary>
    BaselineDefinition GetDefaultBaseline();

    /// <summary>
    /// Gets a baseline by its ID.
    /// </summary>
    BaselineDefinition? GetBaselineById(string baselineId);

    /// <summary>
    /// Gets all control IDs mapped to a specific baseline.
    /// </summary>
    List<string> GetControlIdsForBaseline(string baselineId);
}