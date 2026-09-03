namespace ISCM.Domain.Entities;

public class ScannerConfiguration
{
    public string ConfigurationId { get; set; } = Guid.NewGuid().ToString("N");

    // Cache Settings
    public int CacheMaxAgeMinutes { get; set; } = 30;
    public bool EnableCache { get; set; } = true;

    // Scan Settings
    public int MaxScanDurationMinutes { get; set; } = 60;
    public int ParserTimeoutSeconds { get; set; } = 30;
    public int CheckTimeoutSeconds { get; set; } = 60;

    // Validation Settings
    public bool EnableFingerprintValidation { get; set; } = true;
    public bool EnableFreshnessPolicy { get; set; } = true;

    // Logging
    public bool VerboseLogging { get; set; } = false;
    public bool LogRawOutput { get; set; } = false;

    // Version
    public string Version { get; set; } = "1.0.0";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }

    public void UpdateTimestamp()
    {
        UpdatedAtUtc = DateTime.UtcNow;
    }
}