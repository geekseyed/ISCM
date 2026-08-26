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
    /// Creates the Mining Center Standard baseline based on PDF requirements (4 controls).
    /// </summary>
    public static BaselineDefinition CreateMiningBaseline()
    {
        var baseline = new BaselineDefinition
        {
            BaselineId = "MINING-V1", // ✅ کلمه ERDC کاملاً حذف شد
            Name = "Mining Center Security Hardening",
            Version = "1.0",
            Description = "Security hardening for mining center Windows systems based on practical security measures (USB, WEG, AppLocker, Audit).",
            IsDefault = false,
            IsActive = true,
            ReferenceDocument = "معدنچی.pdf"
        };

        // Map the 4 mining-specific controls exactly as per PDF
        var miningControls = new List<string> { "EXT-01", "EXT-02", "EXT-03", "EXT-04" };

        foreach (var controlId in miningControls)
        {
            baseline.ControlMappings.Add(new BaselineControlMapping
            {
                BaselineId = baseline.BaselineId,
                ControlId = controlId,
                IsRequired = true,
                Priority = 1,
                IsActive = true
            });
        }

        return baseline;
    }

    public static List<BaselineDefinition> GetAllDefaults()
    {
        return new List<BaselineDefinition>
        {
            CreateHosseiniBaseline(),
            CreateMiningBaseline()
        };
    }

    public static BaselineDefinition GetDefault()
    {
        return CreateHosseiniBaseline();
    }
}