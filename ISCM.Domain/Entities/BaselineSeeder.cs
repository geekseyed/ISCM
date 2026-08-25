using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.Entities;

/// <summary>
/// Provides default baseline definitions for the system.
/// </summary>
public static class BaselineSeeder
{
    /// <summary>
    /// Creates the default Hosseini Standard baseline (17 controls).
    /// </summary>
    public static BaselineDefinition CreateHosseiniBaseline()
    {
        var baseline = new BaselineDefinition
        {
            BaselineId = "HOSSEINI-V1",
            Name = "Hosseini Windows 11 Hardening Standard",
            Version = "1.0",
            Description = "Based on CIS Benchmark for Windows 11, adapted for Iranian industrial environments. Includes 17 core security controls.",
            IsDefault = true,
            IsActive = true,
            ReferenceDocument = "Windows11_Hardening_17_Items_Guide_Revised.pdf"
        };

        // Map all 17 baseline controls
        var controlIds = new List<string> { "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17" };

        foreach (var controlId in controlIds)
        {
            baseline.ControlMappings.Add(new BaselineControlMapping
            {
                BaselineId = baseline.BaselineId,
                ControlId = controlId,
                IsRequired = true,
                Priority = 2,
                IsActive = true
            });
        }

        return baseline;
    }

    /// <summary>
    /// Creates the ERDC Mining Standard baseline (1 extended control).
    /// </summary>
    public static BaselineDefinition CreateErdcBaseline()
    {
        var baseline = new BaselineDefinition
        {
            BaselineId = "ERDC-V1",
            Name = "ERDC Mining Additional Hardening",
            Version = "1.0",
            Description = "Additional security measures for ERDC mining environments, including USB restrictions, AppLocker, and advanced Windows Security features.",
            IsDefault = false,
            IsActive = true,
            ReferenceDocument = "معدنچی.pdf"
        };

        // Map the extended control
        baseline.ControlMappings.Add(new BaselineControlMapping
        {
            BaselineId = baseline.BaselineId,
            ControlId = "EXT-01",
            IsRequired = true,
            Priority = 1,
            IsActive = true
        });

        return baseline;
    }

    /// <summary>
    /// Gets all default baselines.
    /// </summary>
    public static List<BaselineDefinition> GetAllDefaults()
    {
        return new List<BaselineDefinition>
        {
            CreateHosseiniBaseline(),
            CreateErdcBaseline()
        };
    }

    /// <summary>
    /// Gets the default baseline (Hosseini).
    /// </summary>
    public static BaselineDefinition GetDefault()
    {
        return CreateHosseiniBaseline();
    }
}