using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class Finding : BaseEntity
{
    public string CheckId { get; private set; } = string.Empty;
    public string Name { get; private set; } = string.Empty;
    public CheckCategory Category { get; private set; }
    public CheckSeverity Severity { get; private set; }
    public CheckStatus Status { get; private set; }
    public string CurrentValue { get; private set; } = string.Empty;
    public string ExpectedValue { get; private set; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public string? RegistryPath { get; private set; }
    public string Recommendation { get; private set; } = string.Empty;
    public string? ErrorMessage { get; private set; }

    // متادیتای غنی (گام ۲۳-د)
    public string CisReference { get; private set; } = "";
    public int RiskScore { get; private set; } = 0;
    public string SourceType { get; private set; } = "";
    public string SourceCommand { get; private set; } = "";
    public IReadOnlyList<string> FixTools { get; private set; } = new List<string>();

    // وضعیت قبلی برای قابلیت Undo (مشترک بین Ignore و FP)
    private CheckStatus? _previousStatus;

    private Finding() { }

    public Finding(
        string checkId,
        string name,
        CheckCategory category,
        CheckSeverity severity,
        CheckStatus status,
        string currentValue,
        string expectedValue,
        string recommendation,
        string? errorMessage = null,
        string description = "",
        string? registryPath = null,
        string cisReference = "",
        int riskScore = 0,
        string sourceType = "",
        string sourceCommand = "",
        IReadOnlyList<string>? fixTools = null)
    {
        if (string.IsNullOrWhiteSpace(checkId))
            throw new ArgumentException("CheckId cannot be empty.", nameof(checkId));
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Name cannot be empty.", nameof(name));

        CheckId = checkId;
        Name = name;
        Category = category;
        Severity = severity;
        Status = status;
        CurrentValue = currentValue;
        ExpectedValue = expectedValue;
        Recommendation = recommendation;
        ErrorMessage = errorMessage;
        Description = description;
        RegistryPath = registryPath;
        CisReference = cisReference;
        RiskScore = riskScore;
        SourceType = sourceType;
        SourceCommand = sourceCommand;
        FixTools = fixTools ?? new List<string>();
    }

    public void Ignore()
    {
        if (Status == CheckStatus.Ignored) return;
        _previousStatus = Status;
        Status = CheckStatus.Ignored;
        MarkModified();
    }

    // EDIT (گام ۲۴): علامت‌گذاری به‌عنوان مثبت کاذب — مستقل از Ignore
    public void MarkFalsePositive()
    {
        if (Status == CheckStatus.FalsePositive) return;
        _previousStatus = Status;
        Status = CheckStatus.FalsePositive;
        MarkModified();
    }

    // EDIT (گام ۲۴): Undo حالا هر دو حالت Ignored و FalsePositive را برمی‌گرداند
    public void Undo()
    {
        if (Status != CheckStatus.Ignored && Status != CheckStatus.FalsePositive) return;
        Status = _previousStatus ?? CheckStatus.NotScanned;
        _previousStatus = null;
        MarkModified();
    }

    // EDIT (گام ۲۴): سرکوب‌شده = Ignored یا FP — مبنای کارت KPI و فیلتر ترکیبی
    public bool IsSuppressed => Status == CheckStatus.Ignored || Status == CheckStatus.FalsePositive;

    public void SetError(string errorMessage)
    {
        Status = CheckStatus.Error;
        ErrorMessage = errorMessage;
        MarkModified();
    }

    public void UpdateResult(CheckStatus newStatus, string newValue)
    {
        Status = newStatus;
        CurrentValue = newValue;
        ErrorMessage = null;
        _previousStatus = null;
        MarkModified();
    }
}