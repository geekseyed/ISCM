namespace ISCM.Application.Interfaces;

/// <summary>
/// Abstraction for resolving storage paths.
/// 
/// Phase 13.2: Decouples persistence location from application logic.
/// The default location is %LOCALAPPDATA%\DefenDoor\Data\ but must be
/// configurable via appsettings.json or environment variables.
/// 
/// Design principles:
/// - Never hard-code absolute paths in consuming code
/// - Support environment variable expansion (e.g., %LOCALAPPDATA%)
/// - Support portable/development/test overrides
/// - Ensure path exists before returning (create if necessary)
/// - Thread-safe and deterministic
/// </summary>
public interface IStoragePathProvider
{
    /// <summary>
    /// Gets the root storage directory for DefenDoor data.
    /// Default: %LOCALAPPDATA%\DefenDoor\Data\
    /// 
    /// The path is guaranteed to exist when this method returns.
    /// </summary>
    string GetRootPath();

    /// <summary>
    /// Gets the full path to the SQLite database file.
    /// Default: {RootPath}\defendoor.db
    /// </summary>
    string GetDatabasePath();

    /// <summary>
    /// Gets the full path to the migrations/history directory.
    /// Default: {RootPath}\Migrations\
    /// </summary>
    string GetMigrationsPath();

    /// <summary>
    /// Gets the full path for temporary files during scan/snapshot operations.
    /// Default: {RootPath}\Temp\
    /// </summary>
    string GetTempPath();

    /// <summary>
    /// Gets the full path for report exports (HTML, PDF, JSON).
    /// Default: {RootPath}\Reports\
    /// </summary>
    string GetReportsPath();

    /// <summary>
    /// Gets the full path for backup files.
    /// Default: {RootPath}\Backups\
    /// </summary>
    string GetBackupsPath();

    /// <summary>
    /// Returns whether the storage location is writable.
    /// Useful for pre-flight checks before persistence operations.
    /// </summary>
    bool IsWritable();

    /// <summary>
    /// Returns diagnostic information about the storage configuration.
    /// Useful for logging and troubleshooting.
    /// </summary>
    StoragePathInfo GetStorageInfo();
}

/// <summary>
/// Diagnostic information about storage configuration.
/// </summary>
public record StoragePathInfo
{
    public string RootPath { get; init; } = string.Empty;
    public string DatabasePath { get; init; } = string.Empty;
    public bool RootExists { get; init; }
    public bool DatabaseExists { get; init; }
    public bool IsWritable { get; init; }
    public long? AvailableBytes { get; init; }
    public string ConfigurationSource { get; init; } = string.Empty;
}