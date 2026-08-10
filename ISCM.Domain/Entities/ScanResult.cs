using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class ScanResult : BaseEntity
{
    public string Hostname { get; private set; } = string.Empty;
    public string IpAddress { get; private set; } = string.Empty;
    public string MacAddress { get; private set; } = string.Empty; // اضافه شد
    public string OsVersion { get; private set; } = string.Empty;
    public string OsBuild { get; private set; } = string.Empty;
    public ScanMode Mode { get; private set; }
    public DateTimeOffset StartedAtUtc { get; private set; }
    public DateTimeOffset? CompletedAtUtc { get; private set; }

    private readonly List<Finding> _findings = new();
    public IReadOnlyCollection<Finding> Findings => _findings.AsReadOnly();

    private ScanResult() { }

    // MacAddress به سازنده اضافه شد
    public ScanResult(string hostname, string ipAddress, string macAddress, string osVersion, string osBuild, ScanMode mode)
    {
        if (string.IsNullOrWhiteSpace(hostname))
            throw new ArgumentException("Hostname cannot be empty.", nameof(hostname));

        Hostname = hostname;
        IpAddress = ipAddress;
        MacAddress = macAddress;
        OsVersion = osVersion;
        OsBuild = osBuild;
        Mode = mode;
        StartedAtUtc = DateTimeOffset.UtcNow;
    }

    public void AddFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (_findings.Any(x => x.CheckId == finding.CheckId))
            throw new InvalidOperationException($"Check '{finding.CheckId}' already exists in this scan.");

        _findings.Add(finding);
        MarkModified();
    }

    public void CompleteScan()
    {
        CompletedAtUtc = DateTimeOffset.UtcNow;
        MarkModified();
    }

    public int PassCount => _findings.Count(f => f.Status == CheckStatus.Pass);
    public int FailCount => _findings.Count(f => f.Status == CheckStatus.Fail);
    public int WarningCount => _findings.Count(f => f.Status == CheckStatus.Warning);

    public int ComplianceScore
    {
        get
        {
            if (_findings.Count == 0) return 0;
            var eligibleChecks = _findings.Count(f => f.Status != CheckStatus.Error && f.Status != CheckStatus.NotScanned && f.Status != CheckStatus.Ignored);
            if (eligibleChecks == 0) return 0;
            return (int)Math.Round((double)PassCount / eligibleChecks * 100);
        }
    }

    public string Grade
    {
        get
        {
            var score = ComplianceScore;
            return score >= 90 ? "A" :
                   score >= 80 ? "B" :
                   score >= 70 ? "C" :
                   score >= 60 ? "D" : "F";
        }
    }
}