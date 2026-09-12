using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

public class ScanHistoryEntry
{
    public DateTime ScanTime { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public int ComplianceScore { get; set; }
    public string Grade { get; set; } = string.Empty;
    public Guid? SnapshotId { get; set; }
}

public class ScanHistoryService
{
    private readonly ISnapshotRepository? _snapshotRepository;
    private readonly List<ScanHistoryEntry> _inMemoryHistory = new();

    public ScanHistoryService(IServiceProvider serviceProvider)
    {
        _snapshotRepository = serviceProvider.GetService<ISnapshotRepository>();
    }

    public IReadOnlyList<ScanHistoryEntry> History => _inMemoryHistory.AsReadOnly();

    public void AddScan(ScanResult result)
    {
        _inMemoryHistory.Insert(0, new ScanHistoryEntry
        {
            ScanTime = DateTime.Now,
            Hostname = result.Hostname,
            OsVersion = result.OsVersion,
            ComplianceScore = result.ComplianceScore,
            Grade = result.Grade
        });
    }

    public async Task LoadFromPersistenceAsync(string? hostname = null)
    {
        if (_snapshotRepository == null) return;

        try
        {
            var summaries = await _snapshotRepository.ListSummariesAsync(hostname);
            _inMemoryHistory.Clear();
            foreach (var summary in summaries)
            {
                _inMemoryHistory.Add(new ScanHistoryEntry
                {
                    ScanTime = summary.CompletedAtUtc.ToLocalTime(),
                    Hostname = summary.Hostname,
                    OsVersion = summary.OsVersion,
                    ComplianceScore = summary.ComplianceScore,
                    Grade = summary.Grade,
                    SnapshotId = summary.SnapshotId
                });
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to load history from persistence: {ex.Message}");
        }
    }

    public void ClearHistory()
    {
        _inMemoryHistory.Clear();
    }
}