using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Application.Services;

public class ScannerConfigurationService : IScannerConfigurationService
{
    private ScannerConfiguration _currentConfiguration;

    public ScannerConfigurationService()
    {
        _currentConfiguration = new ScannerConfiguration();
    }

    public ScannerConfigurationService(ScannerConfiguration initialConfiguration)
    {
        _currentConfiguration = initialConfiguration ?? new ScannerConfiguration();
    }

    public ScannerConfiguration GetCurrentConfiguration()
    {
        return _currentConfiguration;
    }

    public void UpdateConfiguration(ScannerConfiguration configuration)
    {
        if (configuration == null) throw new ArgumentNullException(nameof(configuration));
        _currentConfiguration = configuration;
        _currentConfiguration.UpdateTimestamp();
    }

    public TimeSpan GetCacheMaxAge()
    {
        return TimeSpan.FromMinutes(_currentConfiguration.CacheMaxAgeMinutes);
    }

    public int GetParserTimeoutSeconds()
    {
        return _currentConfiguration.ParserTimeoutSeconds;
    }

    public int GetCheckTimeoutSeconds()
    {
        return _currentConfiguration.CheckTimeoutSeconds;
    }

    public bool IsCacheEnabled()
    {
        return _currentConfiguration.EnableCache;
    }

    public bool IsFingerprintValidationEnabled()
    {
        return _currentConfiguration.EnableFingerprintValidation;
    }
}