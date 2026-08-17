using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Checks;

public class EventLogSizeCheck : IHardeningCheck
{
    private const string BasePath = @"SYSTEM\CurrentControlSet\Services\EventLog";

    public string CheckId => "EVL-001";
    public string Name => "Event Log Size & Retention";
    public CheckCategory Category => CheckCategory.Audit;
    public CheckSeverity Severity => CheckSeverity.Low;

    private static readonly List<SubCheck> SubChecks = new()
    {
        new SubCheck { Id = "EVL-001.1", Title = "Application max log size", Expected = "65536 KB (64 MB)", WhatItDoes = "Enough Application log history.", Recommendation = "MaxSize = 67108864.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application' -Name MaxSize -Value 67108864 -Type DWord", Verification = "Application MaxSize = 67108864.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → Application → Properties", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\Application → MaxSize", GraphicalSteps = "1) eventvwr → Application → Properties → 64MB.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MaxSize", AlternativeToRegistry = "Prefer Event Viewer properties over registry." },
        new SubCheck { Id = "EVL-001.2", Title = "Security max log size", Expected = "131072 KB (128 MB)", WhatItDoes = "Extra space for critical events.", Recommendation = "MaxSize = 134217728.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name MaxSize -Value 134217728 -Type DWord", Verification = "Security MaxSize = 134217728.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → Security → Properties", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\Security → MaxSize", GraphicalSteps = "1) Security → Properties → 128MB.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize", AlternativeToRegistry = "Prefer Event Viewer properties." },
        new SubCheck { Id = "EVL-001.3", Title = "System max log size", Expected = "65536 KB (64 MB)", WhatItDoes = "Enough System log history.", Recommendation = "MaxSize = 67108864.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name MaxSize -Value 67108864 -Type DWord", Verification = "System MaxSize = 67108864.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → System → Properties", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\System → MaxSize", GraphicalSteps = "1) System → Properties → 64MB.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\MaxSize", AlternativeToRegistry = "Prefer Event Viewer properties." },
        new SubCheck { Id = "EVL-001.4", Title = "Setup max log size", Expected = "32768 KB (32 MB)", WhatItDoes = "Retains servicing events.", Recommendation = "MaxSize = 33554432.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup' -Name MaxSize -Value 33554432 -Type DWord", Verification = "Setup MaxSize = 33554432.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → Setup → Properties", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\Setup → MaxSize", GraphicalSteps = "1) Setup → Properties → 32MB.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Setup\MaxSize", AlternativeToRegistry = "Prefer Event Viewer properties." },
        new SubCheck { Id = "EVL-001.5", Title = "Retention method", Expected = "Overwrite as needed (oldest first)", WhatItDoes = "Avoids log halting the system.", Recommendation = "Retention = 0 (overwrite).", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name Retention -Value 0 -Type DWord", Verification = "Retention = 0.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → Retention", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\* → Retention = 0", GraphicalSteps = "1) Properties → 'Overwrite events as needed'.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\Retention", AlternativeToRegistry = "Prefer Event Viewer properties." },
        new SubCheck { Id = "EVL-001.6", Title = "Back up log automatically when full (optional)", Expected = "Enabled", WhatItDoes = "Auto-archives full logs.", Recommendation = "AutoBackupLogFiles = 1.", CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' -Name AutoBackupLogFiles -Value 1 -Type DWord", Verification = "AutoBackupLogFiles = 1.", ConsoleTool = "eventvwr.msc", DestinationLabel = "Event Viewer → Auto-backup", YouAreHere = "Registry Editor (root)", GoTo = "EventLog\\* → AutoBackupLogFiles = 1", GraphicalSteps = "1) Properties → 'Back up log automatically'.", HasRegistryPath = true, RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\AutoBackupLogFiles", AlternativeToRegistry = "Prefer Event Viewer properties." }
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
            { currentValue = $"{size} bytes"; status = CheckStatus.Pass; }
            else { currentValue = v?.ToString() ?? "Missing"; status = CheckStatus.Fail; }
        }
        catch (Exception ex) { errorMessage = ex.Message; status = CheckStatus.Error; }

        return Task.FromResult(new Finding(
            CheckId, Name, Category, Severity, status, currentValue,
            "134217728", "Increase log capacity so security events are not overwritten early.",
            errorMessage: errorMessage,
            description: "Raises Event Log maximum sizes and sets safe retention.",
            registryPath: $@"HKLM\{BasePath}\Security\MaxSize",
            cisReference: "CIS 6.1",
            riskScore: 30,
            sourceType: "RegistryReader",
            sourceCommand: $@"reg query ""HKLM\{BasePath}\Security"" /v MaxSize",
            fixTools: new List<string> { "eventvwr.msc" },
            subChecks: SubChecks));
    }
}