using ISCM.Application.Interfaces;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace ISCM.Infrastructure.Persistence;

/// <summary>
/// Resolves storage paths for DefenDoor persistence.
/// Default: %LOCALAPPDATA%\DefenDoor\Data\
/// Configurable via appsettings.json "Storage:RootPath".
/// </summary>
public class SqliteStoragePathProvider : IStoragePathProvider
{
    private readonly string _rootPath;
    private readonly string _configSource;

    public SqliteStoragePathProvider(IConfiguration configuration)
    {
        var configuredPath = configuration["Storage:RootPath"];

        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            _rootPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DefenDoor",
                "Data");
            _configSource = "Default (LocalApplicationData)";
        }
        else
        {
            _rootPath = Environment.ExpandEnvironmentVariables(configuredPath);
            _configSource = "appsettings.json";
        }

        EnsureDirectoriesExist();
    }

    private void EnsureDirectoriesExist()
    {
        Directory.CreateDirectory(_rootPath);
        Directory.CreateDirectory(GetMigrationsPath());
        Directory.CreateDirectory(GetTempPath());
        Directory.CreateDirectory(GetReportsPath());
        Directory.CreateDirectory(GetBackupsPath());
    }

    public string GetRootPath() => _rootPath;

    public string GetDatabasePath() => Path.Combine(_rootPath, "defendoor.db");

    public string GetMigrationsPath() => Path.Combine(_rootPath, "Migrations");

    public string GetTempPath() => Path.Combine(_rootPath, "Temp");

    public string GetReportsPath() => Path.Combine(_rootPath, "Reports");

    public string GetBackupsPath() => Path.Combine(_rootPath, "Backups");

    public bool IsWritable()
    {
        try
        {
            var testFile = Path.Combine(_rootPath, ".write_test_" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(testFile, "test");
            File.Delete(testFile);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public StoragePathInfo GetStorageInfo()
    {
        var dbPath = GetDatabasePath();
        long? availableBytes = null;
        try
        {
            var root = Path.GetPathRoot(_rootPath);
            if (!string.IsNullOrEmpty(root))
            {
                var driveInfo = new DriveInfo(root);
                availableBytes = driveInfo.AvailableFreeSpace;
            }
        }
        catch { }

        return new StoragePathInfo
        {
            RootPath = _rootPath,
            DatabasePath = dbPath,
            RootExists = Directory.Exists(_rootPath),
            DatabaseExists = File.Exists(dbPath),
            IsWritable = IsWritable(),
            AvailableBytes = availableBytes,
            ConfigurationSource = _configSource
        };
    }
}