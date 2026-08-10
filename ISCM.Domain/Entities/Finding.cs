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

    // این دو پراپرتی اضافه شدند
    public string Description { get; private set; } = string.Empty;
    public string? RegistryPath { get; private set; }

    public string Recommendation { get; private set; } = string.Empty;
    public string? ErrorMessage { get; private set; }

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
        string description = "", // اضافه شد
        string? registryPath = null) // اضافه شد
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
    }

    public void Ignore()
    {
        Status = CheckStatus.Ignored;
        MarkModified();
    }

    public void SetError(string errorMessage)
    {
        Status = CheckStatus.Error;
        ErrorMessage = errorMessage;
        MarkModified();
    }
}