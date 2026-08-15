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

    // EDIT (پیش‌نیاز مرحله ب): متادیتای غنی مطابق UI نهایی —
    // فعلاً مقدار پیش‌فرض خالی؛ در مرحله «د» هر چک مقدار واقعی خودش را می‌دهد.
    public string CisReference { get; private set; } = "";
    public int RiskScore { get; private set; } = 0;
    public string SourceType { get; private set; } = "";
    public string SourceCommand { get; private set; } = "";
    public IReadOnlyList<string> FixTools { get; private set; } = new List<string>();

    // EDIT: وضعیت قبلی برای قابلیت Undo
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

    // EDIT: هنگام Ignore، وضعیت قبلی ذخیره می‌شود تا Undo ممکن باشد.
    public void Ignore()
    {
        if (Status == CheckStatus.Ignored) return;
        _previousStatus = Status;
        Status = CheckStatus.Ignored;
        MarkModified();
    }

    // EDIT: Undo — بازگشت به وضعیت قبل از Ignore
    public void Undo()
    {
        if (Status != CheckStatus.Ignored) return;
        Status = _previousStatus ?? CheckStatus.NotScanned;
        _previousStatus = null;
        MarkModified();
    }

    public void SetError(string errorMessage)
    {
        Status = CheckStatus.Error;
        ErrorMessage = errorMessage;
        MarkModified();
    }

    // EDIT: به‌روزرسانی نتیجه پس از Rescan تکیِ یک چک
    public void UpdateResult(CheckStatus newStatus, string newValue)
    {
        Status = newStatus;
        CurrentValue = newValue;
        ErrorMessage = null;
        _previousStatus = null;
        MarkModified();
    }
}