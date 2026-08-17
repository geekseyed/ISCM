namespace ISCM.Domain.Entities;

// EDIT (گام ۲۶-ادامه): زیرمجموعه‌های آیتم‌های ۱۰/۱۴/۱۵/۱۶ PDF
// (Firewall / Windows Update / Autorun / Secure RDP)
public static partial class GuidanceCatalog
{
    // ── آیتم ۱۰: Windows Defender Firewall ──
    private static readonly bool _fw = Register(
        new SubCheck
        {
            Id = "FW-001.1",
            Title = "Domain Profile — Firewall state",
            Expected = "On",
            WhatItDoes = "Enables firewall protection on domain networks.",
            Recommendation = "Keep the Domain profile on.",
            CliCommand = "Set-NetFirewallProfile -Profile Domain -Enabled True",
            Verification = "Run: Get-NetFirewallProfile -Profile Domain → Enabled = True.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall → Domain Profile → On",
            YouAreHere = "WF.msc (root)",
            GoTo = "WF.msc → Properties → Domain Profile → State = On",
            GraphicalSteps = "1) wf.msc → right-click root → Properties. 2) Domain Profile tab. 3) State = On.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "FW-001.2",
            Title = "Domain Profile — Inbound connections",
            Expected = "Block (default)",
            WhatItDoes = "Blocks unsolicited inbound traffic on domain networks.",
            Recommendation = "Default inbound = Block.",
            CliCommand = "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block",
            Verification = "Get-NetFirewallProfile -Profile Domain → DefaultInboundAction = Block.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall → Domain Profile → Inbound Block",
            YouAreHere = "WF.msc (root)",
            GoTo = "Properties → Domain Profile → Inbound = Block",
            GraphicalSteps = "1) Properties → Domain Profile. 2) Inbound connections = Block.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "FW-001.3",
            Title = "Private Profile — On + Inbound Block",
            Expected = "On / Block",
            WhatItDoes = "Enables firewall and blocks inbound on private networks.",
            Recommendation = "Private profile on, inbound block.",
            CliCommand = "Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block",
            Verification = "Get-NetFirewallProfile -Profile Private → Enabled True, Inbound Block.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall → Private Profile → On/Block",
            YouAreHere = "WF.msc (root)",
            GoTo = "Properties → Private Profile → On + Inbound Block",
            GraphicalSteps = "1) Properties → Private Profile. 2) State On, Inbound Block.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "FW-001.4",
            Title = "Public Profile — On + Block all",
            Expected = "On / Block all",
            WhatItDoes = "Strictest setting for public networks; blocks all inbound.",
            Recommendation = "Public profile on, inbound block.",
            CliCommand = "Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block",
            Verification = "Get-NetFirewallProfile -Profile Public → Enabled True, Inbound Block.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall → Public Profile → On/Block",
            YouAreHere = "WF.msc (root)",
            GoTo = "Properties → Public Profile → On + Inbound Block",
            GraphicalSteps = "1) Properties → Public Profile. 2) State On, Inbound Block.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "FW-001.5",
            Title = "Display a notification / local rules",
            Expected = "No / No",
            WhatItDoes = "Suppresses pop-ups and ignores local user rules in high-security envs.",
            Recommendation = "Disable notifications; apply only GPO rules.",
            CliCommand = "# wf.msc → Properties → each profile → 'Display a notification' = No",
            Verification = "wf.msc → Properties → notification setting = No on all profiles.",
            ConsoleTool = "wf.msc",
            DestinationLabel = "Firewall → Properties → Notifications No",
            YouAreHere = "WF.msc (root)",
            GoTo = "Properties → each profile → Display a notification = No",
            GraphicalSteps = "1) Properties. 2) For each profile set notification = No.",
            HasRegistryPath = false
        });

    // ── آیتم ۱۴: Windows Update ──
    private static readonly bool _wup = Register(
        new SubCheck
        {
            Id = "WUP-001.1",
            Title = "Configure Automatic Updates",
            Expected = "Enabled (option 4)",
            WhatItDoes = "Turns on managed automatic updates; auto-download + scheduled install.",
            Recommendation = "AUOptions = 4 (auto download & schedule).",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -Value 0; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name AUOptions -Value 4",
            Verification = "Get-ItemProperty '...\\WindowsUpdate\\AU' → NoAutoUpdate=0, AUOptions=4.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → Configure Automatic Updates",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\Microsoft\\Windows\\WindowsUpdate\\AU → AUOptions = 4",
            GraphicalSteps = "1) gpedit → Windows Components → Windows Update. 2) Configure Automatic Updates = Enabled, option 4.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows Update over manual registry editing."
        },
        new SubCheck
        {
            Id = "WUP-001.2",
            Title = "Scheduled install day / time",
            Expected = "Every day @ 03:00",
            WhatItDoes = "Installs patches daily during off-hours.",
            Recommendation = "Day=0 (every day), Time=3.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name ScheduledInstallDay -Value 0; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name ScheduledInstallTime -Value 3",
            Verification = "Get-ItemProperty → ScheduledInstallDay=0, ScheduledInstallTime=3.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → Schedule",
            YouAreHere = "Registry Editor (root)",
            GoTo = "WindowsUpdate\\AU → ScheduledInstallDay=0, ScheduledInstallTime=3",
            GraphicalSteps = "1) Configure Automatic Updates → schedule = daily 03:00.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows Update over manual registry editing."
        },
        new SubCheck
        {
            Id = "WUP-001.3",
            Title = "No auto-restart with logged-on users",
            Expected = "Disabled",
            WhatItDoes = "Allows restart to complete patching even if users are logged on.",
            Recommendation = "NoAutoRebootWithLoggedOnUsers = 0.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoRebootWithLoggedOnUsers -Value 0",
            Verification = "Get-ItemProperty → NoAutoRebootWithLoggedOnUsers=0.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "Windows Update → No auto-restart",
            YouAreHere = "Registry Editor (root)",
            GoTo = "WindowsUpdate\\AU → NoAutoRebootWithLoggedOnUsers = 0",
            GraphicalSteps = "1) 'No auto-restart…' = Disabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers",
            AlternativeToRegistry = "Prefer gpedit.msc → Windows Update over manual registry editing."
        });

    // ── آیتم ۱۵: Disable Autorun/Autoplay ──
    private static readonly bool _ard = Register(
        new SubCheck
        {
            Id = "ARD-001.1",
            Title = "Turn off AutoPlay (all drives)",
            Expected = "Enabled — All drives",
            WhatItDoes = "Disables AutoPlay on every drive type, including USB.",
            Recommendation = "NoDriveTypeAutoRun = 255.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",
            Verification = "Get-ItemProperty '...\\Policies\\Explorer' → NoDriveTypeAutoRun=255.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "AutoPlay Policies → Turn off AutoPlay",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\Explorer → NoDriveTypeAutoRun = 255",
            GraphicalSteps = "1) gpedit → Windows Components → AutoPlay. 2) Turn off AutoPlay = Enabled (All drives).",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies over manual registry editing."
        },
        new SubCheck
        {
            Id = "ARD-001.2",
            Title = "Default behavior for AutoRun",
            Expected = "Do not execute any autorun",
            WhatItDoes = "Prevents Windows from running autorun.inf automatically.",
            Recommendation = "NoAutorun = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutorun -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → NoAutorun=1.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "AutoPlay → Default AutoRun behavior",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\Explorer → NoAutorun = 1",
            GraphicalSteps = "1) 'Set the default behavior for AutoRun' = Do not execute.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies over manual registry editing."
        },
        new SubCheck
        {
            Id = "ARD-001.3",
            Title = "Disallow Autoplay for non-volume devices",
            Expected = "Enabled",
            WhatItDoes = "Blocks AutoPlay for MTP phones/cameras.",
            Recommendation = "NoAutoplayfornonVolume = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → NoAutoplayfornonVolume=1.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "AutoPlay → Disallow non-volume",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\Explorer → NoAutoplayfornonVolume = 1",
            GraphicalSteps = "1) 'Disallow Autoplay for non-volume devices' = Enabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutoplayfornonVolume",
            AlternativeToRegistry = "Prefer gpedit.msc → AutoPlay Policies over manual registry editing."
        });

    // ── آیتم ۱۶: Secure RDP (NLA) ──
    private static readonly bool _rdp = Register(
        new SubCheck
        {
            Id = "RDP-001.1",
            Title = "Require NLA for remote connections",
            Expected = "Enabled",
            WhatItDoes = "Forces clients to authenticate before a session is created.",
            Recommendation = "UserAuthentication = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
            Verification = "Get-ItemProperty '...\\RDP-Tcp' → UserAuthentication=1.",
            ConsoleTool = "SystemPropertiesRemote.exe",
            DestinationLabel = "Remote → Allow connections + NLA",
            YouAreHere = "Registry Editor (root)",
            GoTo = "WinStations\\RDP-Tcp → UserAuthentication = 1",
            GraphicalSteps = "1) System Properties → Remote. 2) Allow connections only with NLA.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication",
            AlternativeToRegistry = "Prefer System Properties → Remote over manual registry editing."
        },
        new SubCheck
        {
            Id = "RDP-001.2",
            Title = "Encryption level + secure RPC",
            Expected = "High / Enabled",
            WhatItDoes = "Forces 128-bit encryption and authenticated RPC.",
            Recommendation = "MinEncryptionLevel=3, fEncryptRPCTraffic=1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MinEncryptionLevel -Value 3; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fEncryptRPCTraffic -Value 1",
            Verification = "Get-ItemProperty '...\\Terminal Services' → MinEncryptionLevel=3, fEncryptRPCTraffic=1.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RDP Security → Encryption + RPC",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Terminal Services → MinEncryptionLevel=3, fEncryptRPCTraffic=1",
            GraphicalSteps = "1) gpedit → RDSH → Security. 2) Set encryption High + require secure RPC.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel",
            AlternativeToRegistry = "Prefer gpedit.msc → RDSH Security over manual registry editing."
        },
        new SubCheck
        {
            Id = "RDP-001.3",
            Title = "Always prompt for password",
            Expected = "Enabled",
            WhatItDoes = "Forces password entry at each RDP connection.",
            Recommendation = "fPromptForPassword = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword -Value 1",
            Verification = "Get-ItemProperty → fPromptForPassword=1.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RDP Security → Prompt for password",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Terminal Services → fPromptForPassword = 1",
            GraphicalSteps = "1) 'Always prompt for password upon connection' = Enabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword",
            AlternativeToRegistry = "Prefer gpedit.msc → RDSH Security over manual registry editing."
        },
        new SubCheck
        {
            Id = "RDP-001.4",
            Title = "Session limits (idle / disconnected)",
            Expected = "15 min / 1 min",
            WhatItDoes = "Disconnects idle and ends disconnected sessions quickly.",
            Recommendation = "MaxIdleTime=900000, MaxDisconnectionTime=60000.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxIdleTime -Value 900000; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name MaxDisconnectionTime -Value 60000",
            Verification = "Get-ItemProperty → MaxIdleTime=900000, MaxDisconnectionTime=60000.",
            ConsoleTool = "gpedit.msc",
            DestinationLabel = "RDP → Session time limits",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Terminal Services → MaxIdleTime / MaxDisconnectionTime",
            GraphicalSteps = "1) Set idle limit 15 min, disconnected limit 1 min.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime",
            AlternativeToRegistry = "Prefer gpedit.msc → RDSH Session Limits over manual registry editing."
        });
}