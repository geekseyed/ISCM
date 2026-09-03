using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;

namespace ISCM.Application.Services;

public class ScanContext : IScanContext
{
    public string ScanId { get; } = Guid.NewGuid().ToString("N");
    public string TargetId { get; }
    public DateTime StartedAtUtc { get; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; private set; }
    public ScanMode ScanMode { get; }
    public string ScannerVersion { get; }
    public bool IsCompleted { get; private set; }
    public string? Error { get; private set; }

    public ScanContext(string targetId, ScanMode mode, string scannerVersion = "1.0.0")
    {
        TargetId = targetId ?? throw new ArgumentNullException(nameof(targetId));
        ScanMode = mode;
        ScannerVersion = scannerVersion;
    }

    public bool IsRemediationVerification => ScanMode == ScanMode.RemediationVerification;
    public bool IsRescan => ScanMode == ScanMode.Rescan;

    public void MarkCompleted()
    {
        CompletedAtUtc = DateTime.UtcNow;
        IsCompleted = true;
    }

    public void MarkFailed(string error)
    {
        CompletedAtUtc = DateTime.UtcNow;
        IsCompleted = true;
        Error = error;
    }
}