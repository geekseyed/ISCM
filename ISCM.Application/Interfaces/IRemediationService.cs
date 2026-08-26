using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Service for managing and executing remediation actions.
/// </summary>
public interface IRemediationService
{
    /// <summary>
    /// Gets all available remediation actions.
    /// </summary>
    List<RemediationAction> GetAllRemediations();

    /// <summary>
    /// Gets remediation actions for a specific check.
    /// </summary>
    List<RemediationAction> GetRemediationsForCheck(string checkId);

    /// <summary>
    /// Gets a specific remediation action by ID.
    /// </summary>
    RemediationAction? GetRemediationById(string remediationId);

    /// <summary>
    /// Executes a remediation action.
    /// </summary>
    Task<RemediationHistory> ExecuteRemediationAsync(
        string remediationId,
        string? executedBy = null);

    /// <summary>
    /// Rolls back a remediation action.
    /// </summary>
    Task<RemediationHistory> RollbackRemediationAsync(
        string remediationId,
        string? rolledBackBy = null);

    /// <summary>
    /// Gets the execution history for a remediation.
    /// </summary>
    List<RemediationHistory> GetExecutionHistory(string remediationId);

    /// <summary>
    /// Validates if a remediation can be executed (prerequisites check).
    /// </summary>
    Task<RemediationValidationResult> ValidateRemediationAsync(string remediationId);
}

/// <summary>
/// Result of remediation validation.
/// </summary>
public class RemediationValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}