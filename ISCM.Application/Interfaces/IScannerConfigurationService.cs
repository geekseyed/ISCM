using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IScannerConfigurationService
{
    ScannerConfiguration GetCurrentConfiguration();
    void UpdateConfiguration(ScannerConfiguration configuration);
    TimeSpan GetCacheMaxAge();
    int GetParserTimeoutSeconds();
    int GetCheckTimeoutSeconds();
    bool IsCacheEnabled();
    bool IsFingerprintValidationEnabled();
}