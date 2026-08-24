using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IScanService
{
    int TotalCheckCount { get; }
    Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full, IProgress<string>? progress = null);
    Task<Finding> RescanCheckAsync(string checkId);

    /// <summary>
    /// Rescans a specific SubControl within a Parent Control.
    /// This is more granular than RescanCheckAsync which rescans the entire Parent.
    /// </summary>
    /// <param name="checkId">The Parent Control ID (e.g., "PWD-001")</param>
    /// <param name="subControlId">The specific SubControl ID (e.g., "PWD-001.4")</param>
    /// <returns>The updated Finding for the Parent Control</returns>
    Task<Finding> RescanSubControlAsync(string checkId, string subControlId);
}