using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Application.Evaluators;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class PasswordLengthCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;
    private readonly IEvidenceEvaluator _evaluator;

    public override string CheckId => "PWD-001";
    public override string Name => "Password Policy";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.High;

    private const string PasswordPolicyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public PasswordLengthCheck()
    {
        _registryParser = new RegistryParser();
        _evaluator = new DefaultEvidenceEvaluator();
    }

    public override async Task<Finding> EvaluateAsync()
    {
        // Legacy method: delegate to EvaluateSubControlsAsync and aggregate
        var subControlResults = await EvaluateSubControlsAsync();
        var controlDefinition = ControlCatalog.GetByCheckId(CheckId);

        if (controlDefinition == null)
        {
            controlDefinition = new ControlDefinition
            {
                ControlId = CheckId,
                Title = Name,
                Category = Category,
                Severity = Severity,
                IsBaseline = true,
                TechnicalCheckIds = new() { CheckId },
                SubControls = new()
            };
        }

        var evaluator = new ControlEvaluator();
        return evaluator.EvaluateFromSubControls(controlDefinition, subControlResults);
    }

    /// <summary>
    /// Phase 2.5: Evaluates all 6 password policy settings independently.
    /// </summary>
    public override async Task<List<SubControlResult>> EvaluateSubControlsAsync()
    {
        var results = new List<SubControlResult>();

        // 1. Minimum Password Length (from registry or net accounts)
        results.Add(await EvaluateMinimumPasswordLength());

        // 2. Password History
        results.Add(await EvaluatePasswordHistory());

        // 3. Maximum Password Age
        results.Add(await EvaluateMaximumPasswordAge());

        // 4. Minimum Password Age
        results.Add(await EvaluateMinimumPasswordAge());

        // 5. Password Complexity
        results.Add(await EvaluatePasswordComplexity());

        // 6. Reversible Encryption
        results.Add(await EvaluateReversibleEncryption());

        return results;
    }

    private async Task<SubControlResult> EvaluateMinimumPasswordLength()
    {
        var subControlId = "PWD-001.4";
        var expectedValue = "14 characters";
        var startTime = DateTime.UtcNow;

        try
        {
            // Try registry first
            string rawOutput;
            using (var key = Registry.LocalMachine.OpenSubKey(PasswordPolicyPath))
            {
                var value = key?.GetValue("MinimumPasswordLength");
                rawOutput = value?.ToString() ?? "Not configured";
            }

            // Fallback to net accounts
            if (rawOutput == "Not configured")
            {
                rawOutput = await RunCommandAsync("net", "accounts");
            }

            var parsedValue = _registryParser.Parse(rawOutput, "Registry");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, ">=");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "Registry",
                        SourceName = "MinimumPasswordLength",
                        Command = $"reg query HKLM\\{PasswordPolicyPath} /v MinimumPasswordLength",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "Registry",
                        SourceName = "MinimumPasswordLength",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<SubControlResult> EvaluatePasswordHistory()
    {
        var subControlId = "PWD-001.1";
        var expectedValue = "24 passwords remembered";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, ">=");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        Command = "net accounts",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<SubControlResult> EvaluateMaximumPasswordAge()
    {
        var subControlId = "PWD-001.2";
        var expectedValue = "60 days";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, "<=");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        Command = "net accounts",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<SubControlResult> EvaluateMinimumPasswordAge()
    {
        var subControlId = "PWD-001.3";
        var expectedValue = "1 day";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, ">=");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        Command = "net accounts",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<SubControlResult> EvaluatePasswordComplexity()
    {
        var subControlId = "PWD-001.5";
        var expectedValue = "Enabled";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, "BOOLEAN_TRUE");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        Command = "net accounts",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<SubControlResult> EvaluateReversibleEncryption()
    {
        var subControlId = "PWD-001.6";
        var expectedValue = "Disabled";
        var startTime = DateTime.UtcNow;

        try
        {
            var rawOutput = await RunCommandAsync("net", "accounts");
            var parsedValue = _registryParser.Parse(rawOutput, "PowerShell");
            var (status, reason) = _evaluator.Evaluate(parsedValue, expectedValue, "BOOLEAN_FALSE");

            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = status,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        Command = "net accounts",
                        RawOutput = rawOutput,
                        ParsedValue = parsedValue,
                        ExpectedValue = expectedValue,
                        Evaluation = status,
                        EvaluationReason = reason,
                        Timestamp = DateTime.UtcNow,
                        DurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new SubControlResult
            {
                SubControlId = subControlId,
                Status = CheckStatus.Error,
                EvidenceItems = new List<Evidence>
                {
                    new Evidence
                    {
                        SourceType = "PowerShell",
                        SourceName = "net accounts",
                        RawOutput = ex.Message,
                        ExpectedValue = expectedValue,
                        Evaluation = CheckStatus.Error,
                        EvaluationReason = $"Exception: {ex.Message}",
                        Timestamp = DateTime.UtcNow,
                        Error = ex.Message
                    }
                },
                EvaluatedAt = DateTime.UtcNow
            };
        }
    }

    private static async Task<string> RunCommandAsync(string cmd, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return "Process not started";

            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }
}