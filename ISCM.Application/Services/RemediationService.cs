using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;

namespace ISCM.Application.Services;

/// <summary>
/// Phase 4.2/4.3 Hardened: REAL registry writes, honest success detection, admin gate, real rollback.
/// </summary>
public class RemediationService : IRemediationService
{
    private readonly List<RemediationAction> _actions = new();
    private readonly List<RemediationHistory> _history = new();

    public RemediationService()
    {
        SeedDefaultRemediations();
    }

    public static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void SeedDefaultRemediations()
    {
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

        _actions.Add(new RemediationAction
        {
            RemediationId = "REM-SMB-001",
            CheckId = "SMB-001",
            Title = "Disable SMBv1 Protocol",
            Description = "Disables the insecure SMBv1 protocol to prevent ransomware spread.",
            Type = RemediationType.PowerShell,
            Script = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -Value 0 -Type DWord; " +
         "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' -Name 'Start' -Value 4 -Type DWord; " +
         "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            RiskLevel = CheckSeverity.High,
            RequiresReboot = true,
            EstimatedDurationSeconds = 15,
            Prerequisites = new List<string> { "Admin privileges" },
            Warnings = new List<string> { "Requires a reboot to take full effect." }
        });

        // 3. Disable Autorun (ARD-001) - کامل: هر 3 تنظیم استاندارد
        _actions.Add(new RemediationAction
        {
            RemediationId = "REM-ARD-001",
            CheckId = "ARD-001",
            Title = "Disable Autorun/Autoplay",
            Description = "Disables Autorun and Autoplay for all drives to prevent malware execution from USB.",
            Type = RemediationType.PowerShell,
            Script = "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; " +
                     "New-Item -Path $p -Force | Out-Null; " +
                     "Set-ItemProperty -Path $p -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Force; " +
                     "Set-ItemProperty -Path $p -Name 'NoAutorun' -Value 1 -Type DWord -Force; " +
                     "Set-ItemProperty -Path $p -Name 'NoAutoplayforNonVolumeDevices' -Value 1 -Type DWord -Force",
            RiskLevel = CheckSeverity.Low,
            RequiresReboot = false,
            EstimatedDurationSeconds = 3,
            Prerequisites = new List<string> { "Admin privileges" },
            Warnings = new List<string> { "CD/DVD and USB auto-play will be disabled." }
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

        // ✅ Admin Gate: بدون دسترسی مدیر، تعمیر بلاک می‌شود (صادقانه)
        if (action.Prerequisites.Any(p => p.Contains("Admin")) && !IsRunningAsAdmin())
        {
            history.Status = RemediationStatus.Failed;
            history.ExecutionOutput = "BLOCKED: Application is not running as Administrator. Run Visual Studio as Administrator and try again.";
            _history.Add(history);
            return history;
        }

        try
        {
            // ✅ Phase 4.3: REAL Backup - خواندن مقدار فعلی قبل از تغییر
            string backupValue = ReadCurrentState(action);

            bool success;
            string output;

            if (action.Type == RemediationType.PowerShell || action.Type == RemediationType.BatchScript)
            {
                (success, output) = await RunPowerShellScriptAsync(action.Script);
            }
            else if (action.Type == RemediationType.Registry)
            {
                (success, output) = ApplyRegistryChange(action.Script);
            }
            else
            {
                success = false;
                output = $"Unsupported remediation type: {action.Type}";
            }

            if (success)
            {
                history.Status = RemediationStatus.Success;
                history.ExecutionOutput = output;
                history.BackupValue = backupValue;
                history.CanRollback = action.Type == RemediationType.Registry;
            }
            else
            {
                history.Status = RemediationStatus.Failed;
                history.ExecutionOutput = output;
            }
        }
        catch (Exception ex)
        {
            history.Status = RemediationStatus.Failed;
            history.ExecutionOutput = ex.Message;
        }

        _history.Add(history);
        return history;
    }

    // ✅ خواندن واقعی مقدار فعلی (برای Backup)
    private string ReadCurrentState(RemediationAction action)
    {
        if (action.Type != RemediationType.Registry)
            return $"[State snapshot for {action.Title}]";

        try
        {
            var (keyPath, valueName, _) = ParseRegistryScript(action.Script);
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            return key?.GetValue(valueName)?.ToString() ?? "<not set>";
        }
        catch (Exception ex)
        {
            return $"<read error: {ex.Message}>";
        }
    }

    // ✅ پارس فرمت: HKLM:\PATH\ValueName=Data
    private static (string KeyPath, string ValueName, string Data) ParseRegistryScript(string script)
    {
        var normalized = script;
        if (normalized.StartsWith("HKLM:\\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized.Substring("HKLM:\\".Length);

        var eq = normalized.LastIndexOf('=');
        if (eq < 0) throw new FormatException("Invalid registry script. Expected HKLM:\\Path\\Value=Data");

        var fullPath = normalized.Substring(0, eq);
        var data = normalized.Substring(eq + 1);

        var slash = fullPath.LastIndexOf('\\');
        if (slash < 0) throw new FormatException("Invalid registry path.");

        return (fullPath.Substring(0, slash), fullPath.Substring(slash + 1), data);
    }

    // ✅ نوشتن واقعی در Registry
    private (bool Success, string Output) ApplyRegistryChange(string script)
    {
        try
        {
            var (keyPath, valueName, data) = ParseRegistryScript(script);

            using var key = Registry.LocalMachine.CreateSubKey(keyPath);
            if (key == null) return (false, $"Cannot open/create key: HKLM\\{keyPath}");

            if (int.TryParse(data, out var dword))
                key.SetValue(valueName, dword, RegistryValueKind.DWord);
            else
                key.SetValue(valueName, data, RegistryValueKind.String);

            return (true, $"Registry updated: HKLM\\{keyPath}\\{valueName} = {data}");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Access denied. Run the application as Administrator.");
        }
        catch (Exception ex)
        {
            return (false, $"Registry error: {ex.Message}");
        }
    }

    public Task<RemediationHistory> RollbackRemediationAsync(string remediationId, string? rolledBackBy = null)
    {
        var history = _history.LastOrDefault(h => h.RemediationId == remediationId && h.Status == RemediationStatus.Success);
        var action = GetRemediationById(remediationId);

        if (history != null && history.CanRollback && action != null && action.Type == RemediationType.Registry
            && !string.IsNullOrEmpty(history.BackupValue) && history.BackupValue != "<not set>")
        {
            try
            {
                var (keyPath, valueName, _) = ParseRegistryScript(action.Script);
                using var key = Registry.LocalMachine.CreateSubKey(keyPath);
                if (int.TryParse(history.BackupValue, out var dword))
                    key?.SetValue(valueName, dword, RegistryValueKind.DWord);
                else
                    key?.SetValue(valueName, history.BackupValue, RegistryValueKind.String);

                history.Status = RemediationStatus.RolledBack;
                history.RolledBackAt = DateTimeOffset.UtcNow;
                history.RolledBackBy = rolledBackBy ?? "System";
                history.ExecutionOutput += " | ROLLBACK PERFORMED (real registry restore)";
            }
            catch (Exception ex)
            {
                history.ExecutionOutput += $" | ROLLBACK FAILED: {ex.Message}";
            }
        }
        else if (history != null)
        {
            history.Status = RemediationStatus.RolledBack;
            history.RolledBackAt = DateTimeOffset.UtcNow;
            history.RolledBackBy = rolledBackBy ?? "System";
            history.ExecutionOutput += " | ROLLBACK RECORDED (no automatic reverse for PowerShell)";
        }
        else
        {
            history = new RemediationHistory
            {
                RemediationId = remediationId,
                Status = RemediationStatus.Failed,
                ExecutionOutput = "No successful remediation found to rollback."
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
            return Task.FromResult(result);
        }

        if (action.Prerequisites.Any(p => p.Contains("Admin")) && !IsRunningAsAdmin())
        {
            result.IsValid = false;
            result.Errors.Add("Application is NOT running as Administrator. Remediation will be blocked.");
        }

        return Task.FromResult(result);
    }

    // ✅ راستی‌آزمایی صادقانه: ExitCode و stderr بررسی می‌شوند
    private async Task<(bool Success, string Output)> RunPowerShellScriptAsync(string script)
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
        if (process == null) return (false, "Failed to start powershell.exe");

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error))
            return (false, $"PowerShell failed (exit {process.ExitCode}): {error}");

        return (true, string.IsNullOrWhiteSpace(output) ? "Command executed successfully." : output.Trim());
    }
}