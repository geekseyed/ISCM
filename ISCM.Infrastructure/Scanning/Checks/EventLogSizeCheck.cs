using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class EventLogSizeCheck : IHardeningCheck, IMultiPathCheck
{
    private const string BasePath = @"SYSTEM\CurrentControlSet\Services\EventLog";

    public string CheckId => "EVL-001";
    public string Name => "Event Log Size & Retention";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Low;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "EVL-001.1", Title = "Application log — Specify the maximum log file size (KB)", Expected = "Enabled — 65536 KB (64 MB)",
            WhatItDoes = "Ensures the Application log retains enough history.", Recommendation = "Enable the policy and set Maximum log size (KB) = 65536.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -Value 67108864 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 67108864 (bytes). Note: the policy dialog accepts KB (65536 KB), registry stores bytes.",
            ValueMap = "65536 KB = 67108864 bytes.", CliTokens = "MaxSize: maximum log size in bytes.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB) > Enabled > 65536",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application.\n3) Double-click 'Specify the maximum log file size (KB)'.\n4) Set to Enabled, Maximum log size (KB) = 65536.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -Value 33554432 -Type DWord",
            IgnoreConsequence = "Application log fills quickly and older events are overwritten.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Application over manual registry editing." },
        new SubCheck { Id = "EVL-001.2", Title = "Security log — Specify the maximum log file size (KB)", Expected = "Enabled — 131072 KB (128 MB)",
            WhatItDoes = "Gives the Security log extra capacity for critical events.", Recommendation = "Enable the policy and set Maximum log size (KB) = 131072.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -Value 134217728 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 134217728 (bytes) = 131072 KB.", ValueMap = "131072 KB = 134217728 bytes.", CliTokens = "MaxSize: maximum log size in bytes.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB) > Enabled > 131072",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Administrative Templates > Windows Components > Event Log Service > Security.\n3) Double-click 'Specify the maximum log file size (KB)'.\n4) Set to Enabled, Maximum log size (KB) = 131072.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -Value 67108864 -Type DWord",
            IgnoreConsequence = "Security log fills quickly and critical events are lost.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Security over manual registry editing." },
        new SubCheck { Id = "EVL-001.3", Title = "System log — Specify the maximum log file size (KB)", Expected = "Enabled — 65536 KB (64 MB)",
            WhatItDoes = "Ensures the System log retains enough history.", Recommendation = "Enable the policy and set Maximum log size (KB) = 65536.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -Value 67108864 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 67108864 (bytes).", ValueMap = "65536 KB = 67108864 bytes.", CliTokens = "MaxSize: maximum log size in bytes.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB) > Enabled > 65536",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Administrative Templates > Windows Components > Event Log Service > System.\n3) Double-click 'Specify the maximum log file size (KB)'.\n4) Set to Enabled, Maximum log size (KB) = 65536.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -Value 33554432 -Type DWord",
            IgnoreConsequence = "System log fills quickly and boot/service events are lost.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > System over manual registry editing." },
        new SubCheck { Id = "EVL-001.4", Title = "Setup log — Specify the maximum log file size (KB)", Expected = "Enabled — 32768 KB (32 MB)",
            WhatItDoes = "Retains setup and servicing events for troubleshooting.", Recommendation = "Enable the policy and set Maximum log size (KB) = 32768.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -Value 33554432 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 33554432 (bytes) = 32768 KB.", ValueMap = "32768 KB = 33554432 bytes.", CliTokens = "MaxSize: maximum log size in bytes.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Setup > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup > Specify the maximum log file size (KB) > Enabled > 32768",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Administrative Templates > Windows Components > Event Log Service > Setup.\n3) Double-click 'Specify the maximum log file size (KB)'.\n4) Set to Enabled, Maximum log size (KB) = 32768.\n5) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -Value 1048576 -Type DWord",
            IgnoreConsequence = "Setup log may not retain recent servicing events.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Setup\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Setup over manual registry editing." },
        new SubCheck { Id = "EVL-001.5", Title = "Retention method (Application / Security / System)", Expected = "Overwrite events as needed (oldest first)",
            WhatItDoes = "Prevents the log service from halting when the log is full.", Recommendation = "Set retention to 'Overwrite events as needed' for Application, Security and System logs.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name Retention -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Retention",
            CliCommand = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name Retention -Value 0 -Type DWord }",
            VerifyCli = "@('Application','Security','System') | ForEach-Object { Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name Retention -ErrorAction SilentlyContinue }",
            Verification = "Retention = 0 on all three logs.", ValueMap = "0 = Overwrite as needed, 1 = Retain as long as possible, 0xFFFFFFFF = Do not overwrite.",
            CliTokens = "Retention: behavior when the log is full. 0 is the safe default.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Event Log Service > Application/Security/System > Control Event Log behavior when log reaches max size",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application/Security/System > 'Control Event Log behavior when the log file reaches its maximum size' (modern ADMX name)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application/Security/System > Control Event Log behavior when the log file reaches its maximum size > Overwrite events as needed",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Administrative Templates > Windows Components > Event Log Service.\n3) For each of Application, Security, System:\na) Double-click 'Control Event Log behavior when the log file reaches its maximum size'.\nb) Set to Enabled.\nc) Select 'Overwrite events as needed'.\nd) OK.",
            UndoCli = "# Revert to 'Do not overwrite' is rarely desirable; leave as 0.",
            IgnoreConsequence = "Logs may stop accepting new events when full, breaking audit continuity.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\Retention",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service over manual registry editing." },
        new SubCheck { Id = "EVL-001.6", Title = "Back up log automatically when full (Application / Security / System) — optional", Expected = "Enabled only if you collect archived .evtx files",
            WhatItDoes = "Automatically archives the full log and starts a new one when paired with proper retention.", Recommendation = "Enable only if you have a collection process for the archived .evtx files; otherwise leave Disabled.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name AutoBackupLogFiles -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoBackupLogFiles",
            CliCommand = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -Value 1 -Type DWord }",
            VerifyCli = "@('Application','Security','System') | ForEach-Object { Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -ErrorAction SilentlyContinue }",
            Verification = "AutoBackupLogFiles = 1 on the logs you enabled it for.", ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "AutoBackupLogFiles: automatic archival when the log reaches max size.",
            ConsoleTool = "gpedit.msc", DestinationLabel = "Event Log Service > Application/Security/System > Back up log automatically when full",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application/Security/System > Back up log automatically when full",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application/Security/System > Back up log automatically when full > Enabled",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Administrative Templates > Windows Components > Event Log Service.\n3) For each of Application, Security, System:\na) Double-click 'Back up log automatically when full'.\nb) Set to Enabled only if you have an archiving process.\nc) OK.",
            UndoCli = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -Value 0 -Type DWord }",
            IgnoreConsequence = "Full logs are not archived; old events are overwritten according to retention.",
            HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\AutoBackupLogFiles",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service over manual registry editing." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();

        try
        {
            // Helper to check MaxSize
            bool CheckMaxSize(string logName, long minBytes)
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{BasePath}\{logName}");
                var v = key?.GetValue("MaxSize");
                return v != null && long.TryParse(v.ToString(), out long size) && size >= minBytes;
            }

            // Helper to check Retention
            bool CheckRetention(string logName)
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{BasePath}\{logName}");
                var v = key?.GetValue("Retention");
                return v != null && int.TryParse(v.ToString(), out int ret) && ret == 0;
            }

            // 1. Application MaxSize (64 MB = 67108864 bytes)
            statuses.Add(CheckMaxSize("Application", 67108864) ? CheckStatus.Pass : CheckStatus.Fail);

            // 2. Security MaxSize (128 MB = 134217728 bytes)
            statuses.Add(CheckMaxSize("Security", 134217728) ? CheckStatus.Pass : CheckStatus.Fail);

            // 3. System MaxSize (64 MB)
            statuses.Add(CheckMaxSize("System", 67108864) ? CheckStatus.Pass : CheckStatus.Fail);

            // 4. Setup MaxSize (32 MB = 33554432 bytes)
            statuses.Add(CheckMaxSize("Setup", 33554432) ? CheckStatus.Pass : CheckStatus.Fail);

            // 5. Application Retention
            statuses.Add(CheckRetention("Application") ? CheckStatus.Pass : CheckStatus.Fail);

            // 6. Security Retention
            statuses.Add(CheckRetention("Security") ? CheckStatus.Pass : CheckStatus.Fail);

            // 7. System Retention
            statuses.Add(CheckRetention("System") ? CheckStatus.Pass : CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            string details = $"{passCount}/{statuses.Count} Event Log settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "All logs sized and retention configured",
                "Increase log capacity and clarify retention so security events are not overwritten early.",
                errorMessage: string.Empty,
                description: "Raises Event Log maximum sizes (Application 64 MB, Security 128 MB, System 64 MB, Setup 32 MB) and configures safe retention behavior.",
                registryPath: $@"HKLM\{BasePath}\Security\MaxSize",
                cisReference: "CIS 18.9.5", riskScore: 30, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{BasePath}\Security"" /v MaxSize",
                fixTools: new List<string> { "gpedit.msc", "eventvwr.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Raises Event Log maximum sizes and configures safe retention behavior.",
                registryPath: $@"HKLM\{BasePath}\Security\MaxSize",
                cisReference: "CIS 18.9.5", riskScore: 30, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{BasePath}\Security"" /v MaxSize",
                fixTools: new List<string> { "gpedit.msc", "eventvwr.msc" },
                subChecks: SubChecks));
        }
    }

    // Preserved: 3-Test Verification
    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();
        // Test 1: Registry HKLM برای Security MaxSize
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog\Security");
            if (key != null)
            {
                var v = key.GetValue("MaxSize");
                if (v != null && int.TryParse(v.ToString(), out int size))
                {
                    var passed = size >= 134217728;
                    var mb = size / (1024 * 1024);
                    results.Add(new TestResult("Primary", "Registry (Security MaxSize)", passed, $"MaxSize = {size} bytes ({mb} MB)"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (Security MaxSize)", false, "MaxSize value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (Security MaxSize)", false, "EventLog Security registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (Security MaxSize)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 2: PowerShell Get-WinEvent -ListLog برای بررسی سایز Security
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-WinEvent -ListLog Security | Select-Object -ExpandProperty MaximumSizeInBytes\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                if (!string.IsNullOrWhiteSpace(output) && long.TryParse(output.Trim(), out long size))
                {
                    var passed = size >= 134217728;
                    var mb = size / (1024 * 1024);
                    results.Add(new TestResult("Cross-check", "Get-WinEvent", passed, $"Security MaximumSizeInBytes = {size} ({mb} MB)"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "Get-WinEvent", false, "Could not query Security log size"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "Get-WinEvent", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        // Test 3: wevtutil برای Application log
        try
        {
            var psi = new ProcessStartInfo("wevtutil.exe", "gl Application")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process != null)
            {
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                var maxLine = output.Split('\n').FirstOrDefault(l => l.Contains("maxLogSize:", StringComparison.OrdinalIgnoreCase));
                if (maxLine != null)
                {
                    var parts = maxLine.Split(':');
                    if (parts.Length > 1 && long.TryParse(parts[1].Trim(), out long size))
                    {
                        var passed = size >= 67108864;
                        var mb = size / (1024 * 1024);
                        results.Add(new TestResult("Verification", "wevtutil (Application)", passed, $"maxLogSize = {size} ({mb} MB)"));
                    }
                    else
                    {
                        results.Add(new TestResult("Verification", "wevtutil (Application)", false, "Could not parse maxLogSize"));
                    }
                }
                else
                {
                    results.Add(new TestResult("Verification", "wevtutil (Application)", false, "maxLogSize not found in wevtutil output"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "wevtutil (Application)", false, $"Error: {ex.Message}"));
        }
        return results;
    }

    private static CheckStatus GetWorstStatus(IEnumerable<CheckStatus> statuses)
    {
        if (statuses.Any(s => s == CheckStatus.Fail)) return CheckStatus.Fail;
        if (statuses.Any(s => s == CheckStatus.Error)) return CheckStatus.Error;
        if (statuses.Any(s => s == CheckStatus.Unknown)) return CheckStatus.Unknown;
        return CheckStatus.Pass;
    }
}