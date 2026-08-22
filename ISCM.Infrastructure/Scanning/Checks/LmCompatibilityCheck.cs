using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;

namespace ISCM.Infrastructure.Scanning.Checks;

public class LmCompatibilityCheck : IHardeningCheck, IMultiPathCheck
{
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

    public string CheckId => "LM-001";
    public string Name => "NTLM & LAN Manager Authentication";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.Medium;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "LM-001.1", Title = "Network security: LAN Manager authentication level",
            Expected = "Send NTLMv2 response only. Refuse LM & NTLM",
            WhatItDoes = "Forces stronger NTLM behavior and blocks weak LM/NTLM.",
            Recommendation = "Set LmCompatibilityLevel = 5.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel",
            Verification = "LmCompatibilityLevel = 5.",
            ValueMap = "0 = Send LM & NTLM, 5 = Send NTLMv2 only, Refuse LM & NTLM.",
            CliTokens = "-Name LmCompatibilityLevel: NTLM negotiation level.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → LAN Manager authentication level",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies > Security Options",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level > Send NTLMv2 response only. Refuse LM & NTLM",
            GraphicalSteps = "1) Run secpol.msc.\n2) Navigate to Security Settings > Local Policies > Security Options.\n3) Double-click 'Network security: LAN Manager authentication level'.\n4) Select 'Send NTLMv2 response only. Refuse LM & NTLM'.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 0",
            IgnoreConsequence = "Weak LM/NTLM hashes remain usable by attackers.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options." },
        new SubCheck { Id = "LM-001.2", Title = "Network security: Do not store LAN Manager hash value on next password change",
            Expected = "Enabled",
            WhatItDoes = "Stops storage of weak LM hashes.",
            Recommendation = "Set NoLMHash = 1.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash",
            Verification = "NoLMHash = 1.",
            ValueMap = "1 = Do not store LM hash.",
            CliTokens = "-Name NoLMHash: disables LM hash storage.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Do not store LAN Manager hash value on next password change",
            GraphicalPathFull = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change",
            ConsolePath = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            YouAreHere = "secpol.msc > Security Settings > Local Policies > Security Options",
            GoTo = "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change > Enabled",
            GraphicalSteps = "1) Same Security Options node.\n2) Double-click 'Network security: Do not store LAN Manager hash value on next password change'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 0",
            IgnoreConsequence = "Weak LM hash stored and crackable.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash",
            AlternativeToRegistry = "Prefer secpol.msc > Security Options." }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown"; CheckStatus status = CheckStatus.Error; string? errorMessage = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaPath);
            var v = key?.GetValue("LmCompatibilityLevel");
            if (v != null && int.TryParse(v.ToString(), out int level) && level >= 5)
            {
                currentValue = $"NTLM Level {level}";
                status = CheckStatus.Pass;
            }
            else
            {
                currentValue = v?.ToString() ?? "Not set (defaults to level 3)";
                status = CheckStatus.Fail;
            }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "Send NTLMv2 response only. Refuse LM & NTLM",
            "Force NTLMv2 and prevent LM/NTLM usage to protect against downgrade attacks.",
            errorMessage: errorMessage,
            description: "Hardens NTLM authentication to refuse weak LM and NTLM protocols.",
            registryPath: $@"HKLM\{LsaPath}\LmCompatibilityLevel",
            cisReference: "CIS 2.3.10.8",
            riskScore: 60,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{LsaPath}"" /v LmCompatibilityLevel",
            fixTools: new List<string> { "secpol.msc" },
            subChecks: SubChecks));
    }

    // اجرای ۳ روش تست واقعی
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        // Test 1: Registry برای LmCompatibilityLevel
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaPath);
            if (key != null)
            {
                var v = key.GetValue("LmCompatibilityLevel");
                if (v != null && int.TryParse(v.ToString(), out int level))
                {
                    var passed = level >= 5;
                    var desc = level switch
                    {
                        0 => "Send LM & NTLM",
                        1 => "Use LM & NTLM (negotiate)",
                        2 => "Send NTLM only",
                        3 => "Send NTLMv2 only",
                        4 => "NTLMv2 + DC refuses LM",
                        5 => "NTLMv2 + DC refuses LM & NTLM",
                        _ => $"Unknown ({level})"
                    };
                    results.Add(new TestResult("Primary", "Registry (LmCompatibilityLevel)", passed, $"Level = {level} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (LmCompatibilityLevel)", false, "Value not found (defaults to level 3)"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (LmCompatibilityLevel)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (LmCompatibilityLevel)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 2: Registry برای NoLMHash
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaPath);
            if (key != null)
            {
                var v = key.GetValue("NoLMHash");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Cross-check", "Registry (NoLMHash)", passed, $"NoLMHash = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Registry (NoLMHash)", false, "NoLMHash value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Cross-check", "Registry (NoLMHash)", false, "Registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Registry (NoLMHash)", false, $"Error: {ex.Message}"));
        }

        await Task.Delay(50);

        // Test 3: secedit export با ایجاد پوشه
        try
        {
            if (!Directory.Exists(@"C:\temp"))
            {
                Directory.CreateDirectory(@"C:\temp");
            }

            var psi = new ProcessStartInfo("secedit.exe", "/export /cfg \"C:\\temp\\lmcheck.inf\" /areas SECURITYPOLICY")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (File.Exists(@"C:\temp\lmcheck.inf"))
            {
                var content = await File.ReadAllTextAsync(@"C:\temp\lmcheck.inf");
                var line = content.Split('\n').FirstOrDefault(l => l.Contains("LMCompatibilityLevel", StringComparison.OrdinalIgnoreCase));
                if (line != null)
                {
                    var parts = line.Split('=');
                    if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int level))
                    {
                        var passed = level >= 5;
                        results.Add(new TestResult("Verification", "secedit (LMCompatibilityLevel)", passed, $"LMCompatibilityLevel = {level}"));
                    }
                    else
                    {
                        results.Add(new TestResult("Verification", "secedit (LMCompatibilityLevel)", false, "Could not parse level"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Verification", "secedit (LMCompatibilityLevel)", false, "LMCompatibilityLevel not found in export"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "secedit (LMCompatibilityLevel)", false, "secedit export failed"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "secedit (LMCompatibilityLevel)", false, $"Error: {ex.Message}"));
        }

        return results;
    }
}