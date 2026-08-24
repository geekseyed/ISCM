using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace ISCM.Infrastructure.Scanning.Checks;

[SupportedOSPlatform("windows")]
public class RdpNlaCheck : IHardeningCheck, IMultiPathCheck
{
    private const string RdpTcpPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string TsPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    public string CheckId => "RDP-001";
    public string Name => "Secure RDP (Network Level Authentication)";
    public CheckCategory Category => CheckCategory.Network;
    public CheckSeverity Severity => CheckSeverity.High;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "RDP-001.1", Title = "Require user authentication for remote connections by using Network Level Authentication",
            Expected = "Enabled",
            WhatItDoes = "Requires authentication before a full RDP session is created.",
            Recommendation = "Enable the NLA policy under Remote Desktop Session Host > Security.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication",
            Verification = "UserAuthentication = 1.",
            ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name UserAuthentication: master switch for NLA.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Security → Require user authentication (NLA)",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using Network Level Authentication",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security",
            YouAreHere = "gpedit.msc > RD Session Host > Security",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using Network Level Authentication > Enabled",
            GraphicalSteps = "1) Run gpedit.msc.\n2) Navigate to Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security.\n3) Double-click 'Require user authentication for remote connections by using Network Level Authentication'.\n4) Set to Enabled.\n5) Click OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 0",
            IgnoreConsequence = "RDP sessions can be established before authentication, exposing the login screen to unauthenticated attackers.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Security over manual registry editing." },
        new SubCheck { Id = "RDP-001.2", Title = "Set client connection encryption level",
            Expected = "Enabled — High Level",
            WhatItDoes = "Enforces stronger RDP session encryption.",
            Recommendation = "Set MinEncryptionLevel = 3 (High).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MinEncryptionLevel",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MinEncryptionLevel -Value 3 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MinEncryptionLevel",
            Verification = "MinEncryptionLevel = 3 (High).",
            ValueMap = "1 = Low, 2 = Client Compatible, 3 = High, 4 = FIPS.",
            CliTokens = "-Name MinEncryptionLevel: RDP encryption strength.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Security → Set client connection encryption level",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Set client connection encryption level",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security",
            YouAreHere = "gpedit.msc > RD Session Host > Security",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Set client connection encryption level > Enabled > High Level",
            GraphicalSteps = "1) Open the same Security node.\n2) Double-click 'Set client connection encryption level'.\n3) Set to Enabled.\n4) Select 'High Level'.\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MinEncryptionLevel",
            IgnoreConsequence = "RDP sessions may use weaker encryption levels.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Security." },
        new SubCheck { Id = "RDP-001.3", Title = "Require secure RPC communication",
            Expected = "Enabled",
            WhatItDoes = "Requires authenticated and encrypted RPC communication.",
            Recommendation = "Enable fEncryptRPCTraffic.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fEncryptRPCTraffic",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fEncryptRPCTraffic -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fEncryptRPCTraffic",
            Verification = "fEncryptRPCTraffic = 1.",
            ValueMap = "1 = Enabled, 0 = Disabled.",
            CliTokens = "-Name fEncryptRPCTraffic: secure RPC for RDP.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Security → Require secure RPC",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require secure RPC communication",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security",
            YouAreHere = "gpedit.msc > RD Session Host > Security",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require secure RPC communication > Enabled",
            GraphicalSteps = "1) Open the same Security node.\n2) Double-click 'Require secure RPC communication'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fEncryptRPCTraffic -Value 0",
            IgnoreConsequence = "RPC traffic between RDP client and server is not encrypted.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Security." },
        new SubCheck { Id = "RDP-001.4", Title = "Always prompt for password upon connection",
            Expected = "Enabled",
            WhatItDoes = "Forces password entry on each connection.",
            Recommendation = "Enable fPromptForPassword.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword -Value 1 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword",
            Verification = "fPromptForPassword = 1.",
            ValueMap = "1 = Enabled.",
            CliTokens = "-Name fPromptForPassword: always prompt for password.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Security → Always prompt for password",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Always prompt for password upon connection",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security",
            YouAreHere = "gpedit.msc > RD Session Host > Security",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Always prompt for password upon connection > Enabled",
            GraphicalSteps = "1) Same Security node.\n2) Double-click 'Always prompt for password upon connection'.\n3) Set to Enabled.\n4) OK.",
            UndoCli = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword -Value 0",
            IgnoreConsequence = "Saved credentials may be silently used without user confirmation.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Security." },
        new SubCheck { Id = "RDP-001.5", Title = "Limit number of connections",
            Expected = "Configured (e.g. 2)",
            WhatItDoes = "Restricts concurrent RDP sessions.",
            Recommendation = "Set MaxInstanceCount to a small number.",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxInstanceCount",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxInstanceCount -Value 2 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxInstanceCount",
            Verification = "MaxInstanceCount = 2 (or configured value).",
            ValueMap = "MaxInstanceCount = concurrent session limit.",
            CliTokens = "-Name MaxInstanceCount: max concurrent sessions.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Connections → Limit number of connections",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections > Limit number of connections",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections",
            YouAreHere = "gpedit.msc > RD Session Host > Connections",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections > Limit number of connections > Enabled > 2",
            GraphicalSteps = "1) Navigate to RD Session Host > Connections.\n2) Double-click 'Limit number of connections'.\n3) Set to Enabled.\n4) Enter 2 (or other value).\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxInstanceCount",
            IgnoreConsequence = "Unlimited concurrent RDP sessions allowed.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxInstanceCount",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Connections." },
        new SubCheck { Id = "RDP-001.6", Title = "Set time limit for active but idle RDS sessions",
            Expected = "15 minutes",
            WhatItDoes = "Disconnects idle RDP sessions.",
            Recommendation = "Set MaxIdleTime = 900000 (15 minutes in ms).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxIdleTime",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxIdleTime -Value 900000 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxIdleTime",
            Verification = "MaxIdleTime = 900000 (ms).",
            ValueMap = "900000 ms = 15 minutes.",
            CliTokens = "-Name MaxIdleTime: idle disconnect time (ms).",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Session Time Limits → Active but idle sessions",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits > Set time limit for active but idle Remote Desktop Services sessions",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits",
            YouAreHere = "gpedit.msc > RD Session Host > Session Time Limits",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits > Set time limit for active but idle Remote Desktop Services sessions > Enabled > 15 minutes",
            GraphicalSteps = "1) Navigate to RD Session Host > Session Time Limits.\n2) Double-click 'Set time limit for active but idle Remote Desktop Services sessions'.\n3) Set to Enabled.\n4) Select 15 minutes.\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxIdleTime",
            IgnoreConsequence = "Idle RDP sessions remain active indefinitely.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Session Time Limits." },
        new SubCheck { Id = "RDP-001.7", Title = "Set time limit for disconnected sessions",
            Expected = "1 minute or End immediately",
            WhatItDoes = "Ends disconnected sessions quickly.",
            Recommendation = "Set MaxDisconnectionTime = 60000 (1 minute in ms).",
            CheckCurrentCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxDisconnectionTime",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxDisconnectionTime -Value 60000 -Type DWord",
            VerifyCli = "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxDisconnectionTime",
            Verification = "MaxDisconnectionTime = 60000 (ms) or 0 (End immediately).",
            ValueMap = "60000 ms = 1 minute; 0 = End immediately.",
            CliTokens = "-Name MaxDisconnectionTime: disconnected session timeout (ms).",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RD Session Host → Session Time Limits → Disconnected sessions",
            GraphicalPathFull = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits > Set time limit for disconnected sessions",
            ConsolePath = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits",
            YouAreHere = "gpedit.msc > RD Session Host > Session Time Limits",
            GoTo = "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits > Set time limit for disconnected sessions > Enabled > 1 minute",
            GraphicalSteps = "1) Same Session Time Limits node.\n2) Double-click 'Set time limit for disconnected sessions'.\n3) Set to Enabled.\n4) Select 1 minute (or End immediately).\n5) OK.",
            UndoCli = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxDisconnectionTime",
            IgnoreConsequence = "Disconnected RDP sessions linger, keeping user context active.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime",
            AlternativeToRegistry = "Prefer gpedit.msc > RD Session Host > Session Time Limits." }
    };

    public Task<Finding> EvaluateAsync()
    {
        var statuses = new List<CheckStatus>();
        string details = string.Empty;

        try
        {
            using var rdpKey = Registry.LocalMachine.OpenSubKey(RdpTcpPath);
            var nlaVal = rdpKey?.GetValue("UserAuthentication");
            if (nlaVal != null && nlaVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            using var tsKey = Registry.LocalMachine.OpenSubKey(TsPath);
            var encVal = tsKey?.GetValue("MinEncryptionLevel");
            if (encVal != null && int.TryParse(encVal.ToString(), out int enc) && enc >= 3) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var rpcVal = tsKey?.GetValue("fEncryptRPCTraffic");
            if (rpcVal != null && rpcVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var promptVal = tsKey?.GetValue("fPromptForPassword");
            if (promptVal != null && promptVal.ToString() == "1") statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var maxConnVal = tsKey?.GetValue("MaxInstanceCount");
            if (maxConnVal != null && int.TryParse(maxConnVal.ToString(), out int maxConn) && maxConn > 0 && maxConn <= 5) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var idleVal = tsKey?.GetValue("MaxIdleTime");
            if (idleVal != null && int.TryParse(idleVal.ToString(), out int idle) && idle == 900000) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var discVal = tsKey?.GetValue("MaxDisconnectionTime");
            if (discVal != null && int.TryParse(discVal.ToString(), out int disc) && (disc == 60000 || disc == 0)) statuses.Add(CheckStatus.Pass);
            else statuses.Add(CheckStatus.Fail);

            var finalStatus = GetWorstStatus(statuses);
            int passCount = statuses.Count(s => s == CheckStatus.Pass);
            details = $"{passCount}/{statuses.Count} RDP settings compliant";

            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, finalStatus, details,
                "All 7 RDP settings configured",
                "Harden RDP with NLA, encryption, and session limits to prevent unauthorized remote access.",
                errorMessage: string.Empty,
                description: "Configures Remote Desktop with Network Level Authentication, strong encryption, and session management controls.",
                registryPath: $@"HKLM\{RdpTcpPath}\UserAuthentication",
                cisReference: "CIS 18.10.9.1", riskScore: 80, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RdpTcpPath}"" /v UserAuthentication",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new Finding(
                CheckId, Name, Category, Severity, CheckStatus.Error, "Error", "N/A", "Error",
                errorMessage: ex.Message,
                description: "Configures Remote Desktop with Network Level Authentication, strong encryption, and session management controls.",
                registryPath: $@"HKLM\{RdpTcpPath}\UserAuthentication",
                cisReference: "CIS 18.10.9.1", riskScore: 80, sourceType: "RegistryReader",
                sourceCommand: $@"reg query ""HKLM\{RdpTcpPath}"" /v UserAuthentication",
                fixTools: new List<string> { "gpedit.msc" },
                subChecks: SubChecks));
        }
    }

    public async Task<List<TestResult>> RunMultipleTestsAsync()
    {
        var results = new List<TestResult>();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpTcpPath);
            if (key != null)
            {
                var v = key.GetValue("UserAuthentication");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1;
                    results.Add(new TestResult("Primary", "Registry (NLA UserAuthentication)", passed, $"UserAuthentication = {val}"));
                }
                else
                {
                    results.Add(new TestResult("Primary", "Registry (NLA UserAuthentication)", false, "UserAuthentication value not found"));
                }
            }
            else
            {
                results.Add(new TestResult("Primary", "Registry (NLA UserAuthentication)", false, "RDP-Tcp registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Primary", "Registry (NLA UserAuthentication)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MinEncryptionLevel\"")
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
                if (!string.IsNullOrWhiteSpace(output) && int.TryParse(output.Trim(), out int level))
                {
                    var passed = level == 3;
                    var desc = level switch { 1 => "Low", 2 => "Client Compatible", 3 => "High", 4 => "FIPS", _ => $"Unknown ({level})" };
                    results.Add(new TestResult("Cross-check", "PowerShell (MinEncryptionLevel)", passed, $"MinEncryptionLevel = {level} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Cross-check", "PowerShell (MinEncryptionLevel)", false, "MinEncryptionLevel not configured"));
                }
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Cross-check", "PowerShell (MinEncryptionLevel)", false, $"Error: {ex.Message}"));
        }
        await Task.Delay(50);

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpTcpPath);
            if (key != null)
            {
                var v = key.GetValue("SecurityLayer");
                if (v != null && int.TryParse(v.ToString(), out int val))
                {
                    var passed = val == 1 || val == 2;
                    var desc = val switch { 0 => "RDP Security Layer (weak)", 1 => "Negotiate (recommended)", 2 => "SSL/TLS (strongest)", _ => $"Unknown ({val})" };
                    results.Add(new TestResult("Verification", "Registry (RDP-Tcp SecurityLayer)", passed, $"SecurityLayer = {val} ({desc})"));
                }
                else
                {
                    results.Add(new TestResult("Verification", "Registry (RDP-Tcp SecurityLayer)", true, "SecurityLayer not set (default = Negotiate)"));
                }
            }
            else
            {
                results.Add(new TestResult("Verification", "Registry (RDP-Tcp SecurityLayer)", false, "RDP-Tcp registry key not found"));
            }
        }
        catch (Exception ex)
        {
            results.Add(new TestResult("Verification", "Registry (RDP-Tcp SecurityLayer)", false, $"Error: {ex.Message}"));
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