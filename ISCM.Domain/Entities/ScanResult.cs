using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class ScanResult : BaseEntity
{
    public string Hostname { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; private set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public ScanMode Mode { get; private set; }
    public DateTimeOffset StartedAtUtc { get; private set; }
    public DateTimeOffset? CompletedAtUtc { get; private set; }

    private readonly List<Finding> _findings = new();
    public List<Finding> Findings { get; set; } = new();
    private ScanResult() { }

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

    public void ReplaceFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var existing = _findings.FirstOrDefault(x => x.CheckId == finding.CheckId);
        if (existing != null) _findings.Remove(existing);
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
    public int WarningCount => _findings.Count(f => f.Status == CheckStatus.Unknown);

    // EDIT (گام ۲۴): یافته‌های سرکوب‌شده (Ignored + FP) برای کارت KPI
    public int SuppressedCount => _findings.Count(f => f.IsSuppressed);

    // EDIT (گام ۲۴): موارد بحرانی باز (Fail + Critical) برای کارت KPI
    public int CriticalOpenCount => _findings.Count(f => f.Status == CheckStatus.Fail && f.Severity == CheckSeverity.Critical);

    // EDIT (گام ۲۴): ریسک باز (Fail + Warn) برای کارت KPI
    public int OpenRiskCount => _findings.Count(f => f.Status == CheckStatus.Fail || f.Status == CheckStatus.Unknown);

    public int ComplianceScore
    {
        get
        {
            if (_findings.Count == 0) return 0;
            // EDIT: FalsePositive هم مثل Ignored/Error/NotScanned از مخرج امتیاز حذف می‌شود
            var eligibleChecks = _findings.Count(f =>
                f.Status != CheckStatus.Error &&
                f.Status != CheckStatus.NotScanned &&
                f.Status != CheckStatus.Ignored &&
                f.Status != CheckStatus.FalsePositive);
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