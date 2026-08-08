using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class ScanResult : BaseEntity
{
    public string Hostname { get; private set; } = string.Empty;
    public string IpAddress { get; private set; } = string.Empty;
    public string OsVersion { get; private set; } = string.Empty;
    public ScanMode Mode { get; private set; }
    public DateTimeOffset StartedAtUtc { get; private set; }
    public DateTimeOffset? CompletedAtUtc { get; private set; }

    // لیست خصوصی نتایج (کپسوله‌سازی)
    private readonly List<Finding> _findings = new();

    // لیست عمومی فقط‌خواندنی برای اینکه UI بتواند آن را ببیند
    public IReadOnlyCollection<Finding> Findings => _findings.AsReadOnly();

    private ScanResult() { }

    public ScanResult(string hostname, string ipAddress, string osVersion, ScanMode mode)
    {
        if (string.IsNullOrWhiteSpace(hostname))
            throw new ArgumentException("Hostname cannot be empty.", nameof(hostname));

        Hostname = hostname;
        IpAddress = ipAddress;
        OsVersion = osVersion;
        Mode = mode;
        StartedAtUtc = DateTimeOffset.UtcNow;
    }

    // متد افزودن یک نتیجه به اسکن
    public void AddFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        // جلوگیری از تکرار یک چک در یک اسکن
        if (_findings.Any(x => x.CheckId == finding.CheckId))
            throw new InvalidOperationException($"Check '{finding.CheckId}' already exists in this scan.");

        _findings.Add(finding);
        MarkModified();
    }

    // متد پایان اسکن
    public void CompleteScan()
    {
        CompletedAtUtc = DateTimeOffset.UtcNow;
        MarkModified();
    }

    // محاسبه تعداد موارد Pass شده
    public int PassCount => _findings.Count(f => f.Status == CheckStatus.Pass);

    // محاسبه تعداد موارد Fail شده
    public int FailCount => _findings.Count(f => f.Status == CheckStatus.Fail);

    // محاسبه تعداد موارد Warning
    public int WarningCount => _findings.Count(f => f.Status == CheckStatus.Warning);

    // محاسبه امتیاز کلی (Score)
    // فرمول: (تعداد کل - تعداد خطاها) تقسیم بر تعداد کل ضربدر 100
    public int ComplianceScore
    {
        get
        {
            if (_findings.Count == 0) return 0;

            // مواردی که واقعاً ارزیابی شده‌اند (Error نباشند)
            var eligibleChecks = _findings.Count(f => f.Status != CheckStatus.Error && f.Status != CheckStatus.NotScanned);
            if (eligibleChecks == 0) return 0;

            return (int)Math.Round((double)PassCount / eligibleChecks * 100);
        }
    }

    // محاسبه نمره (Grade) الفبایی
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
