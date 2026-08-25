using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Services;

/// <summary>
/// Implementation of IBaselineService using BaselineSeeder for default data.
/// </summary>
public class BaselineService : IBaselineService
{
    private readonly List<BaselineDefinition> _baselines;

    public BaselineService()
    {
        // Initialize with default baselines from seeder
        _baselines = BaselineSeeder.GetAllDefaults();
    }

    public List<BaselineDefinition> GetAllBaselines()
    {
        return _baselines;
    }

    public BaselineDefinition GetDefaultBaseline()
    {
        return _baselines.FirstOrDefault(b => b.IsDefault)
               ?? _baselines.First();
    }

    public BaselineDefinition? GetBaselineById(string baselineId)
    {
        return _baselines.FirstOrDefault(b => b.BaselineId == baselineId);
    }

    public List<string> GetControlIdsForBaseline(string baselineId)
    {
        var baseline = GetBaselineById(baselineId);
        if (baseline == null) return new List<string>();

        return baseline.ControlMappings
            .Where(m => m.IsActive)
            .Select(m => m.ControlId)
            .ToList();
    }
}