using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IScannerConfigurationService
{
    ScannerConfiguration GetCurrentConfiguration();
    void UpdateConfiguration(ScannerConfiguration configuration);
    TimeSpan GetCacheMaxAge();
    int GetParserTimeoutSeconds();
    int GetCheckTimeoutSeconds();

    /// <summary>
    /// Phase 12.11: Returns the configured maximum degree of parallelism for scan execution.
    /// Returns Environment.ProcessorCount if value is 0 or negative.
    /// </summary>
    int GetMaxDegreeOfParallelism();

    bool IsCacheEnabled();
    bool IsFingerprintValidationEnabled();
}