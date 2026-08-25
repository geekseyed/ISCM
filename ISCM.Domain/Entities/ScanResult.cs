using ISCM.Domain.Common;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

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

    public string? BaselineId { get; set; }
    public BaselineDefinition? Baseline { get; set; }

  
    private readonly List<Finding> _findings = new();

    // ✅ اصلاح حیاتی: اتصال پراپرتی عمومی به لیست خصوصی
    public List<Finding> Findings => _findings;

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

        // ✅ اصلاح: به جای پرتاب خطا، یافتۀ قدیمی را جایگزین می‌کنیم تا از Duplicate جلوگیری شود
        ReplaceFinding(finding);
    }

    public void ReplaceFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var existing = _findings.FirstOrDefault(x => x.CheckId == finding.CheckId);
        if (existing != null)
        {
            _findings.Remove(existing);
        }
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

    public int SuppressedCount => _findings.Count(f => f.IsSuppressed);
    public int CriticalOpenCount => _findings.Count(f => f.Status == CheckStatus.Fail && f.Severity == CheckSeverity.Critical);
    public int OpenRiskCount => _findings.Count(f => f.Status == CheckStatus.Fail || f.Status == CheckStatus.Unknown);

    public int ComplianceScore
    {
        get
        {
            if (_findings.Count == 0) return 0;
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