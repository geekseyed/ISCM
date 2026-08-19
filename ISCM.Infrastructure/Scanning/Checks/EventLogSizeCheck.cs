using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class EventLogSizeCheck : IHardeningCheck
{
    // Scanner reads Security log MaxSize as the combined signal.
    private const string BasePath = @"SYSTEM\CurrentControlSet\Services\EventLog";

    public string CheckId => "EVL-001";
    public string Name => "Event Log Size & Retention";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Low;

    // Revised PDF item 17 — size, retention and auto-backup under Event Log Service.
    private static readonly List<SubCheck> SubChecks = new()
    {
        // ── 17.1 Application log size ──
        new SubCheck
        {
            Id = "EVL-001.1",
            Title = "Application log — Specify the maximum log file size (KB)",
            Expected = "Enabled — 65536 KB (64 MB)",
            WhatItDoes = "Ensures the Application log retains enough history.",
            Recommendation = "Enable the policy and set Maximum log size (KB) = 65536.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -Value 67108864 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 67108864 (bytes). Note: the policy dialog accepts KB (65536 KB), registry stores bytes.",
            ValueMap = "65536 KB = 67108864 bytes.",
            CliTokens = "MaxSize: maximum log size in bytes.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application > 'Specify the maximum log file size (KB)' > Enabled > 65536 KB",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application.\n" +
                "3) Double-click 'Specify the maximum log file size (KB)'.\n" +
                "4) Set to Enabled, Maximum log size (KB) = 65536.\n" +
                "5) OK.",

            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -Value 33554432 -Type DWord",
            IgnoreConsequence = "Application log fills quickly and older events are overwritten.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Application over manual registry editing."
        },

        // ── 17.2 Security log size ──
        new SubCheck
        {
            Id = "EVL-001.2",
            Title = "Security log — Specify the maximum log file size (KB)",
            Expected = "Enabled — 131072 KB (128 MB)",
            WhatItDoes = "Gives the Security log extra capacity for critical events.",
            Recommendation = "Enable the policy and set Maximum log size (KB) = 131072.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -Value 134217728 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 134217728 (bytes) = 131072 KB.",
            ValueMap = "131072 KB = 134217728 bytes.",
            CliTokens = "MaxSize: maximum log size in bytes.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > 'Specify the maximum log file size (KB)' > Enabled > 131072 KB",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Administrative Templates > Windows Components > Event Log Service > Security.\n" +
                "3) Double-click 'Specify the maximum log file size (KB)'.\n" +
                "4) Set to Enabled, Maximum log size (KB) = 131072.\n" +
                "5) OK.",

            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -Value 67108864 -Type DWord",
            IgnoreConsequence = "Security log fills quickly and critical events are lost.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Security over manual registry editing."
        },

        // ── 17.3 System log size ──
        new SubCheck
        {
            Id = "EVL-001.3",
            Title = "System log — Specify the maximum log file size (KB)",
            Expected = "Enabled — 65536 KB (64 MB)",
            WhatItDoes = "Ensures the System log retains enough history.",
            Recommendation = "Enable the policy and set Maximum log size (KB) = 65536.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -Value 67108864 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 67108864 (bytes).",
            ValueMap = "65536 KB = 67108864 bytes.",
            CliTokens = "MaxSize: maximum log size in bytes.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > System > 'Specify the maximum log file size (KB)' > Enabled > 65536 KB",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Administrative Templates > Windows Components > Event Log Service > System.\n" +
                "3) Double-click 'Specify the maximum log file size (KB)'.\n" +
                "4) Set to Enabled, Maximum log size (KB) = 65536.\n" +
                "5) OK.",

            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -Value 33554432 -Type DWord",
            IgnoreConsequence = "System log fills quickly and boot/service events are lost.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > System over manual registry editing."
        },

        // ── 17.4 Setup log size ──
        new SubCheck
        {
            Id = "EVL-001.4",
            Title = "Setup log — Specify the maximum log file size (KB)",
            Expected = "Enabled — 32768 KB (32 MB)",
            WhatItDoes = "Retains setup and servicing events for troubleshooting.",
            Recommendation = "Enable the policy and set Maximum log size (KB) = 32768.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxSize",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -Value 33554432 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -ErrorAction SilentlyContinue",
            Verification = "MaxSize = 33554432 (bytes) = 32768 KB.",
            ValueMap = "32768 KB = 33554432 bytes.",
            CliTokens = "MaxSize: maximum log size in bytes.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Administrative Templates > Windows Components > Event Log Service > Setup > Specify the maximum log file size (KB)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup > Specify the maximum log file size (KB)",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Setup > 'Specify the maximum log file size (KB) > Enabled > 32768",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Administrative Templates > Windows Components > Event Log Service > Setup.\n" +
                "3) Double-click 'Specify the maximum log file size (KB)'.\n" +
                "4) Set to Enabled, Maximum log size (KB) = 32768.\n" +
                "5) OK.",

            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -Value 1048576 -Type DWord",
            IgnoreConsequence = "Setup log may not retain recent servicing events.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Setup\MaxSize",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service > Setup over manual registry editing."
        },

        // ── 17.5 Retention method (combined across the three main logs) ──
        new SubCheck
        {
            Id = "EVL-001.5",
            Title = "Retention method (Application / Security / System)",
            Expected = "Overwrite events as needed (oldest first)",
            WhatItDoes = "Prevents the log service from halting when the log is full.",
            Recommendation = "Set retention to 'Overwrite events as needed' for Application, Security and System logs.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name Retention -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Retention",
            CliCommand = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name Retention -Value 0 -Type DWord }",
            VerifyCli = "@('Application','Security','System') | ForEach-Object { Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name Retention -ErrorAction SilentlyContinue }",
            Verification = "Retention = 0 on all three logs.",
            ValueMap = "0 = Overwrite as needed, 1 = Retain as long as possible, 0xFFFFFFFF = Do not overwrite.",
            CliTokens = "Retention: behavior when the log is full. 0 is the safe default.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Event Log Service > Application/Security/System > Control Event Log behavior when log reaches max size",
            GraphicalPathFull =
                "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > " +
                "Application/Security/System > 'Control Event Log behavior when the log file reaches its maximum size' (modern ADMX name)\n" +
                "Legacy path on some consoles: Computer Configuration > Windows Settings > Security Settings > Event Log > " +
                "Application/Security/System > 'Retention method for application/security/system log'",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Each of Application / Security / System > 'Control Event Log behavior...' > Overwrite events as needed",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Administrative Templates > Windows Components > Event Log Service.\n" +
                "3) For each of Application, Security, System:\n" +
                "   a) Double-click 'Control Event Log behavior when the log file reaches its maximum size'.\n" +
                "   b) Set to Enabled.\n" +
                "   c) Select 'Overwrite events as needed' (or the closest wording).\n" +
                "   d) OK.\n" +
                "4) On consoles using the legacy label: Security Settings > Event Log > 'Retention method for ... log' → Overwrite events as needed.",

            UndoCli = "# Revert to 'Do not overwrite' is rarely desirable; leave as 0.",
            IgnoreConsequence = "Logs may stop accepting new events when full, breaking audit continuity.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\Retention",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service over manual registry editing."
        },

        // ── 17.6 Back up log automatically when full (optional, combined) ──
        new SubCheck
        {
            Id = "EVL-001.6",
            Title = "Back up log automatically when full (Application / Security / System) — optional",
            Expected = "Enabled only if you collect archived .evtx files",
            WhatItDoes = "Automatically archives the full log and starts a new one when paired with proper retention.",
            Recommendation = "Enable only if you have a collection process for the archived .evtx files; otherwise leave Disabled.",

            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name AutoBackupLogFiles -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AutoBackupLogFiles",
            CliCommand = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -Value 1 -Type DWord }",
            VerifyCli = "@('Application','Security','System') | ForEach-Object { Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -ErrorAction SilentlyContinue }",
            Verification = "AutoBackupLogFiles = 1 on the logs you enabled it for.",
            ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "AutoBackupLogFiles: automatic archival when the log reaches max size.",

            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Event Log Service > Application/Security/System > Back up log automatically when full",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application/Security/System > Back up log automatically when full",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Event Log Service",
            YouAreHere = "gpedit.msc > Administrative Templates > Windows Components > Event Log Service",
            GoTo = "Each of Application / Security / System > 'Back up log automatically when full' > Enabled",
            GraphicalSteps =
                "1) Run gpedit.msc.\n" +
                "2) Navigate to Administrative Templates > Windows Components > Event Log Service.\n" +
                "3) For each of Application, Security, System:\n" +
                "   a) Double-click 'Back up log automatically when full'.\n" +
                "   b) Set to Enabled only if you have an archiving process.\n" +
                "   c) OK.",

            UndoCli = "@('Application','Security','System') | ForEach-Object { Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$_\" -Name AutoBackupLogFiles -Value 0 -Type DWord }",
            IgnoreConsequence = "Full logs are not archived; old events are overwritten according to retention.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\AutoBackupLogFiles",
            AlternativeToRegistry = "Prefer gpedit.msc > Event Log Service over manual registry editing."
        }
    };

    public Task<Finding> EvaluateAsync()
    {
        string currentValue = "Unknown";
        CheckStatus status = CheckStatus.Error;
        string? errorMessage = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{BasePath}\Security");
            var v = key?.GetValue("MaxSize");

            if (v != null && int.TryParse(v.ToString(), out int size) && size >= 134217728)
            {
                currentValue = $"Security MaxSize = {size} bytes";
                status = CheckStatus.Pass;
            }
            else
            {
                currentValue = v?.ToString() ?? "Missing";
                status = CheckStatus.Fail;
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            status = CheckStatus.Error;
            currentValue = $"Error: {ex.GetType().Name}";
        }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "134217728",
            "Increase log capacity and clarify retention so security events are not overwritten early.",
            errorMessage: errorMessage,
            description: "Raises Event Log maximum sizes (Application 64 MB, Security 128 MB, System 64 MB, Setup 32 MB) and configures safe retention behavior.",
            registryPath: $@"HKLM\{BasePath}\Security\MaxSize",
            cisReference: "CIS 18.9.5",
            riskScore: 30,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{BasePath}\Security"" /v MaxSize",
            fixTools: new List<string> { "gpedit.msc", "eventvwr.msc" },
            subChecks: SubChecks));
    }
}