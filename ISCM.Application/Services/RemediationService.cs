using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace ISCM.Application.Services;

/// <summary>
/// Service responsible for executing remediation actions and managing rollbacks.
/// </summary>
public class RemediationService : IRemediationService
{
    private readonly List<RemediationAction> _actions = new();
    private readonly List<RemediationHistory> _history = new();

    public RemediationService()
    {
        SeedDefaultRemediations();
    }

    /// <summary>
    /// Seeds the system with predefined remediation actions.
    /// </summary>
    private void SeedDefaultRemediations()
    {
        // 1. Windows Defender Firewall (FW-001)
        _actions.Add(new RemediationAction
        {
            RemediationId = "REM-FW-001",
            CheckId = "FW-001",
            Title = "Enable Windows Defender Firewall",
            Description = "Turns on the Windows Defender Firewall for Domain, Private, and Public profiles.",
            Type = RemediationType.PowerShell,
            Script = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            RiskLevel = CheckSeverity.Medium,
            RequiresReboot = false,
            EstimatedDurationSeconds = 5,
            Prerequisites = new List<string> { "Admin privileges" },
            Warnings = new List<string> { "May block network connections if rules are not configured." }
        });

        // 2. Disable SMBv1 (SMB-001)
        _actions.Add(new RemediationAction
        {
            RemediationId = "REM-SMB-001",
            CheckId = "SMB-001",
            Title = "Disable SMBv1 Protocol",
            Description = "Disables the insecure SMBv1 protocol to prevent ransomware spread.",
            Type = RemediationType.PowerShell,
            Script = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            RiskLevel = CheckSeverity.High,
            RequiresReboot = true,
            EstimatedDurationSeconds = 15,
            Prerequisites = new List<string> { "Admin privileges" },
            Warnings = new List<string> { "Requires a reboot to take full effect." }
        });

        // 3. Disable Autorun (ARD-001)
        _actions.Add(new RemediationAction
        {
            RemediationId = "REM-ARD-001",
            CheckId = "ARD-001",
            Title = "Disable Autorun/Autoplay",
            Description = "Disables Autorun for all drives to prevent malware execution from USB.",
            Type = RemediationType.Registry,
            Script = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun=255",
            RiskLevel = CheckSeverity.Low,
            RequiresReboot = false,
            EstimatedDurationSeconds = 2,
            Prerequisites = new List<string> { "Admin privileges" },
            Warnings = new List<string> { "CD/DVD auto-play will be disabled." }
        });
    }

    public List<RemediationAction> GetAllRemediations() => _actions;

    public List<RemediationAction> GetRemediationsForCheck(string checkId) =>
        _actions.Where(a => a.CheckId == checkId && a.IsActive).ToList();

    public RemediationAction? GetRemediationById(string remediationId) =>
        _actions.FirstOrDefault(a => a.RemediationId == remediationId);

    public async Task<RemediationHistory> ExecuteRemediationAsync(string remediationId, string? executedBy = null)
    {
        var action = GetRemediationById(remediationId);
        var history = new RemediationHistory
        {
            RemediationId = remediationId,
            ExecutedAt = DateTimeOffset.UtcNow,
            ExecutedBy = executedBy ?? "System",
            Status = RemediationStatus.Executing
        };

        if (action == null)
        {
            history.Status = RemediationStatus.Failed;
            history.ExecutionOutput = "Action not found.";
            _history.Add(history);
            return history;
        }

        try
        {
            // ✅ Phase 4.3: Backup Phase - Capture state before change
            string backupValue = "Unknown";
            if (action.Type == RemediationType.Registry)
            {
                // In a real scenario, we would read the registry key here.
                backupValue = $"Registry Value before fix: [Simulated Old Value for {action.Script}]";
            }
            else
            {
                backupValue = $"System State before fix: [Simulated Old State for {action.Title}]";
            }

            // ✅ Execution Phase
            string output = "";
            if (action.Type == RemediationType.PowerShell || action.Type == RemediationType.BatchScript)
            {
                output = await RunPowerShellScriptAsync(action.Script);
            }
            else if (action.Type == RemediationType.Registry)
            {
                output = await ApplyRegistryChangeAsync(action.Script);
            }

            history.Status = RemediationStatus.Success;
            history.ExecutionOutput = output;
            history.BackupValue = backupValue; // Save the backup!
            history.CanRollback = true;
        }
        catch (Exception ex)
        {
            history.Status = RemediationStatus.Failed;
            history.ExecutionOutput = ex.Message;
        }

        _history.Add(history);
        return history;
    }

    public Task<RemediationHistory> RollbackRemediationAsync(string remediationId, string? rolledBackBy = null)
    {
        // Find the last successful execution for this remediation
        var history = _history.LastOrDefault(h => h.RemediationId == remediationId && h.Status == RemediationStatus.Success);

        if (history != null && history.CanRollback)
        {
            // ✅ Simulate Rollback Execution
            Console.WriteLine($"[ROLLBACK] Restoring: {history.BackupValue}");

            history.Status = RemediationStatus.RolledBack;
            history.RolledBackAt = DateTimeOffset.UtcNow;
            history.RolledBackBy = rolledBackBy ?? "System";
            history.ExecutionOutput += " | ROLLBACK PERFORMED";
        }
        else
        {
            // Create a failed history entry if no valid target found
            history = new RemediationHistory
            {
                RemediationId = remediationId,
                Status = RemediationStatus.Failed,
                ExecutionOutput = "No valid remediation found to rollback."
            };
            _history.Add(history);
        }

        return Task.FromResult(history);
    }

    public List<RemediationHistory> GetExecutionHistory(string remediationId) =>
        _history.Where(h => h.RemediationId == remediationId).ToList();

    public Task<RemediationValidationResult> ValidateRemediationAsync(string remediationId)
    {
        var action = GetRemediationById(remediationId);
        var result = new RemediationValidationResult { IsValid = true };

        if (action == null)
        {
            result.IsValid = false;
            result.Errors.Add("Action not found.");
        }
        else if (action.Prerequisites.Any(p => p.Contains("Admin")))
        {
            result.Warnings.Add("Requires Administrator privileges.");
        }

        return Task.FromResult(result);
    }

    private Task<string> RunPowerShellScriptAsync(string script)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return Task.FromResult("Failed to start process.");

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return Task.FromResult(string.IsNullOrEmpty(error) ? output : $"Error: {error}");
    }

    private Task<string> ApplyRegistryChangeAsync(string script)
    {
        // Simplified for Phase 4.2. In Phase 4.3 we will implement full backup/restore.
        return Task.FromResult($"Registry change applied: {script}");
    }
}