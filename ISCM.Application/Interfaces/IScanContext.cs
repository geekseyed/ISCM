using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IScanContext
{
    string ScanId { get; }
    string TargetId { get; }
    DateTime StartedAtUtc { get; }
    DateTime? CompletedAtUtc { get; }
    ScanMode ScanMode { get; }
    string ScannerVersion { get; }
    bool IsCompleted { get; }

    void MarkCompleted();
    void MarkFailed(string error);
}