namespace ISCM.Domain.Entities;

// EDIT (گام ۲۶-ادامه): زیرمجموعه‌های آیتم‌های ۱ و ۸ PDF (Password Policy + Security Options)
public static partial class GuidanceCatalog
{
    // ── آیتم ۱: Password Policy ──
    private static readonly bool _pwd = Register(
        new SubCheck
        {
            Id = "PWD-001.1",
            Title = "Enforce password history",
            Expected = "24 passwords remembered",
            WhatItDoes = "Prevents users from reusing recent passwords.",
            Recommendation = "Keep history at 24 so old passwords cannot be recycled.",
            CliCommand = "# secpol.msc → Account Policies → Password Policy → Enforce password history = 24",
            Verification = "secpol.msc → Password Policy → 'Enforce password history' shows 24.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Enforce password history",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Enforce password history → 24",
            GraphicalSteps = "1) Expand Account Policies. 2) Click Password Policy. 3) Double-click 'Enforce password history'. 4) Set 24.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "PWD-001.2",
            Title = "Maximum password age",
            Expected = "60 days",
            WhatItDoes = "Forces users to change their password periodically.",
            Recommendation = "Set 60 days to limit exposure of stale credentials.",
            CliCommand = "# secpol.msc → Password Policy → Maximum password age = 60",
            Verification = "'Maximum password age' shows 60.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Maximum password age",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Maximum password age → 60",
            GraphicalSteps = "1) Password Policy. 2) Double-click 'Maximum password age'. 3) Set 60.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "PWD-001.3",
            Title = "Minimum password age",
            Expected = "1 day",
            WhatItDoes = "Stops users from cycling through passwords to bypass history.",
            Recommendation = "Set 1 day so a password cannot be changed repeatedly in one sitting.",
            CliCommand = "# secpol.msc → Password Policy → Minimum password age = 1",
            Verification = "'Minimum password age' shows 1.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Minimum password age",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Minimum password age → 1",
            GraphicalSteps = "1) Password Policy. 2) Double-click 'Minimum password age'. 3) Set 1.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "PWD-001.4",
            Title = "Minimum password length",
            Expected = "14 characters",
            WhatItDoes = "Ensures passwords are long enough to resist brute-force attacks.",
            Recommendation = "Enforce at least 14 characters.",
            CliCommand = "net accounts /minpwlen:14",
            Verification = "Run: net accounts → 'Minimum password length' shows 14.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Minimum password length",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Minimum password length → 14",
            GraphicalSteps = "1) Password Policy. 2) Double-click 'Minimum password length'. 3) Set 14.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "PWD-001.5",
            Title = "Password must meet complexity requirements",
            Expected = "Enabled",
            WhatItDoes = "Requires uppercase, lowercase, numbers, and symbols.",
            Recommendation = "Keep complexity enabled.",
            CliCommand = "# secpol.msc → Password Policy → Password complexity = Enabled",
            Verification = "'Password must meet complexity requirements' shows Enabled.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Complexity requirements",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Complexity requirements → Enabled",
            GraphicalSteps = "1) Password Policy. 2) Double-click complexity setting. 3) Enable.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "PWD-001.6",
            Title = "Store passwords using reversible encryption",
            Expected = "Disabled",
            WhatItDoes = "Prevents passwords from being stored in a recoverable (weak) form.",
            Recommendation = "Always Disabled.",
            CliCommand = "# secpol.msc → Password Policy → Reversible encryption = Disabled",
            Verification = "'Store passwords using reversible encryption' shows Disabled.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Password Policy → Reversible encryption",
            YouAreHere = "Local Security Policy (root) → Account Policies",
            GoTo = "Account Policies → Password Policy → Reversible encryption → Disabled",
            GraphicalSteps = "1) Password Policy. 2) Double-click reversible encryption. 3) Disable.",
            HasRegistryPath = false
        });

    // ── آیتم ۸ (بخش UAC) ──
    private static readonly bool _uac = Register(
        new SubCheck
        {
            Id = "UAC-001.1",
            Title = "Run all administrators in Admin Approval Mode",
            Expected = "Enabled",
            WhatItDoes = "Forces admins to confirm elevation, mitigating silent privilege abuse.",
            Recommendation = "Keep UAC on (EnableLUA = 1).",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord",
            Verification = "Run: Get-ItemProperty 'HKLM:\\...\\Policies\\System' → EnableLUA = 1. Restart required.",
            ConsoleTool = "UserAccountControlSettings.exe",
            DestinationLabel = "UAC Settings → Notify (default)",
            YouAreHere = "Registry Editor (root)",
            GoTo = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System → EnableLUA = 1",
            GraphicalSteps = "1) Open UserAccountControlSettings. 2) Move slider to default (notify). 3) OK.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
            AlternativeToRegistry = "Prefer the UAC settings dialog (UserAccountControlSettings.exe) over manual registry editing."
        },
        new SubCheck
        {
            Id = "UAC-001.2",
            Title = "Behavior of the elevation prompt for administrators",
            Expected = "Prompt for consent on the secure desktop",
            WhatItDoes = "Requires elevation prompts to appear on the secure desktop.",
            Recommendation = "Set ConsentPromptBehaviorAdmin = 2.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord",
            Verification = "Get-ItemProperty → ConsentPromptBehaviorAdmin = 2.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Elevation prompt behavior",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\System → ConsentPromptBehaviorAdmin = 2",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'User Account Control: Behavior of the elevation prompt…'. 3) Choose 'Prompt for consent on the secure desktop'.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin",
            AlternativeToRegistry = "Use secpol.msc → Security Options instead of manual registry editing."
        },
        new SubCheck
        {
            Id = "UAC-001.3",
            Title = "Detect application installations and prompt for elevation",
            Expected = "Enabled",
            WhatItDoes = "Catches installer attempts that need admin rights.",
            Recommendation = "Set EnableInstallerDetection = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → EnableInstallerDetection = 1.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Detect application installations",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Policies\\System → EnableInstallerDetection = 1",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Detect application installations…' → Enabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection",
            AlternativeToRegistry = "Use secpol.msc → Security Options instead of manual registry editing."
        });

    // ── آیتم ۸ (بخش LM / NTLM) ──
    private static readonly bool _lm = Register(
        new SubCheck
        {
            Id = "LM-001.1",
            Title = "LAN Manager authentication level",
            Expected = "Send NTLMv2 only. Refuse LM & NTLM",
            WhatItDoes = "Forces the strongest NTLM variant and blocks weak ones.",
            Recommendation = "Set LmCompatibilityLevel = 5.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord",
            Verification = "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' → LmCompatibilityLevel = 5.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → LAN Manager authentication level",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Control\\Lsa → LmCompatibilityLevel = 5",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Network security: LAN Manager authentication level'. 3) 'Send NTLMv2 response only. Refuse LM & NTLM'.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel",
            AlternativeToRegistry = "Use secpol.msc → Security Options instead of manual registry editing."
        },
        new SubCheck
        {
            Id = "LM-001.2",
            Title = "Do not store LAN Manager hash value on next password change",
            Expected = "Enabled",
            WhatItDoes = "Stops Windows from storing the weak LM hash.",
            Recommendation = "Set NoLMHash = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → NoLMHash = 1.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Do not store LM hash",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Control\\Lsa → NoLMHash = 1",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Do not store LAN Manager hash…' → Enabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash",
            AlternativeToRegistry = "Use secpol.msc → Security Options instead of manual registry editing."
        });

    // ── آیتم ۸ (بخش Administrator / blank passwords) ──
    private static readonly bool _adm = Register(
        new SubCheck
        {
            Id = "ADM-001.1",
            Title = "Accounts: Administrator account status",
            Expected = "Disabled",
            WhatItDoes = "Disables the built-in Administrator account.",
            Recommendation = "Disable the built-in Administrator; use named admin accounts instead.",
            CliCommand = "net user Administrator /active:no",
            Verification = "Run: net user Administrator → 'Account active' shows No.",
            ConsoleTool = "lusrmgr.msc",
            DestinationLabel = "Users → Administrator → Properties → Disabled",
            YouAreHere = "Local Users and Groups (root) → Users",
            GoTo = "Users → Administrator → Properties → uncheck 'Account is active'",
            GraphicalSteps = "1) lusrmgr.msc → Users. 2) Right-click Administrator → Properties. 3) Check 'Account is disabled'.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "ADM-001.2",
            Title = "Accounts: Rename administrator account",
            Expected = "Unique non-obvious name",
            WhatItDoes = "Hides the well-known 'Administrator' name from attackers.",
            Recommendation = "Rename the SID -500 account to a unique name.",
            CliCommand = "$a = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }; Rename-LocalUser -SID $a.SID -NewName 'SysOps-X1'",
            Verification = "Get-LocalUser | Where SID -like '*-500' → Name is not 'Administrator'.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Rename administrator account",
            YouAreHere = "Local Security Policy (root) → Local Policies",
            GoTo = "Security Options → 'Accounts: Rename administrator account' → set unique name",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Rename administrator account'. 3) Enter unique name.",
            HasRegistryPath = false
        },
        new SubCheck
        {
            Id = "ADM-001.3",
            Title = "Limit local account use of blank passwords to console logon only",
            Expected = "Enabled",
            WhatItDoes = "Stops blank-password local accounts from being used over the network.",
            Recommendation = "Set LimitBlankPasswordUse = 1.",
            CliCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 1 -Type DWord",
            Verification = "Get-ItemProperty → LimitBlankPasswordUse = 1.",
            ConsoleTool = "secpol.msc",
            DestinationLabel = "Security Options → Limit blank password use",
            YouAreHere = "Registry Editor (root)",
            GoTo = "Control\\Lsa → LimitBlankPasswordUse = 1",
            GraphicalSteps = "1) secpol.msc → Security Options. 2) 'Limit local account use of blank passwords…' → Enabled.",
            HasRegistryPath = true,
            RegistryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse",
            AlternativeToRegistry = "Use secpol.msc → Security Options instead of manual registry editing."
        });
}