using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class ScanResult : BaseEntity
{
    public string ScanId { get; set; }
    public string Hostname { get; set; }
    public string IpAddress { get; set; }
    public string MacAddress { get; set; }
    public string OsVersion { get; set; }
    public int OsBuild { get; set; }
    public ScanMode Mode { get; set; }
    public DateTime StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public string? BaselineId { get; set; }
    public BaselineDefinition? Baseline { get; set; }
    public List<Finding> Findings { get; set; } = new();
    public List<ControlResult> ControlResults { get; set; } = new();

    public ScanResult() { }

    public ScanResult(string hostname, string ipAddress, string macAddress, string osVersion, string osBuild, ScanMode mode)
    {
        ScanId = Guid.NewGuid().ToString("N");
        Hostname = hostname;
        IpAddress = ipAddress;
        MacAddress = macAddress;
        OsVersion = osVersion;
        OsBuild = int.TryParse(osBuild, out var build) ? build : 0;
        Mode = mode;
        StartedAtUtc = DateTime.UtcNow;
        Findings = new List<Finding>();
        ControlResults = new List<ControlResult>();
    }

    public void AddFinding(Finding finding)
    {
        Findings.Add(finding);
    }

    public void CompleteScan()
    {
        CompletedAtUtc = DateTime.UtcNow;
    }

    public string Grade
    {
        get
        {
            var score = ComplianceScore;
            if (score >= 90) return "A+";
            if (score >= 80) return "A";
            if (score >= 70) return "B";
            if (score >= 60) return "C";
            if (score >= 50) return "D";
            return "F";
        }
    }

    public int WarningCount => Findings.Count(f => f.Status == CheckStatus.Unknown);

    public int ComplianceScore
    {
        get
        {
            var eligibleChecks = Findings.Count(f =>
                f.Status != CheckStatus.Error &&
                f.Status != CheckStatus.NotScanned &&
                f.Status != CheckStatus.Ignored &&
                f.Status != CheckStatus.FalsePositive);
            return eligibleChecks == 0 ? 0 : (int)Math.Round((double)PassCount / eligibleChecks * 100);
        }
    }

    public int PassCount => Findings.Count(f => f.Status == CheckStatus.Pass);
    public int FailCount => Findings.Count(f => f.Status == CheckStatus.Fail);
}