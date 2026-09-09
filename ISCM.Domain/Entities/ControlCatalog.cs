using System.Collections.Generic;
using System.Linq;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Catalog of all parent controls (17 baseline + 3 extended checks).
/// Names and IDs match the PDF and DI registrations exactly.
///
/// Phase 10.2: All SubControls now have ExpectedValueType and Operator populated.
/// Phase 10.8: WUP-001 SubControls updated to match check output types (Integer/String).
/// Phase 11.0: Migrated ADM-001.1/2/3 → SEC-001.6/7/8, added new ADM-001.1 (admin count).
///             Populated EXT-01 (DEF-001), EXT-02 (USB-001), EXT-03 (ALG-001) SubControls.
/// </summary>
public static class ControlCatalog
{
    private static readonly List<ControlDefinition> _controls = new()
    {
        // ═══════════════════════════════════════════════════════════════
        // BASELINE CONTROLS (17 items from PDF)
        // ═══════════════════════════════════════════════════════════════

        // 1. Password Policy (6 SubControls)
        new ControlDefinition
        {
            ControlId = "01", BaselineId = "Hosseini-01", Title = "Password Policy",
            Description = "Defines rules for password strength, age, and history to prevent weak or reused credentials.",
            Category = CheckCategory.Account, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "PWD-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "PWD-001.1", SettingName = "Enforce password history", ExpectedValue = "24 passwords remembered", Description = "Prevents users from reusing recent passwords.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "PWD-001.2", SettingName = "Maximum password age", ExpectedValue = "60 days", Description = "Forces periodic password changes.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.LessOrEqual },
                new SubControlDefinition { SubControlId = "PWD-001.3", SettingName = "Minimum password age", ExpectedValue = "1 day", Description = "Stops rapid password cycling to bypass history.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "PWD-001.4", SettingName = "Minimum password length", ExpectedValue = "14 characters", Description = "Raises resistance to brute-force.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "PWD-001.5", SettingName = "Password must meet complexity requirements", ExpectedValue = "Enabled", Description = "Requires mixed character classes.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "secedit" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "PWD-001.6", SettingName = "Store passwords using reversible encryption", ExpectedValue = "Disabled", Description = "Prevents weak recoverable storage.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "01", EvidenceSources = new() { "secedit" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 2. Account Lockout Policy (3 SubControls)
        new ControlDefinition
        {
            ControlId = "02", BaselineId = "Hosseini-02", Title = "Account Lockout Policy",
            Description = "Locks user accounts after repeated failed logon attempts to mitigate brute-force attacks.",
            Category = CheckCategory.Account, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "LCK-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "LCK-001.1", SettingName = "Account lockout threshold", ExpectedValue = "5 invalid logon attempts", Description = "Number of failed logons before lockout.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "02", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.LessOrEqual },
                new SubControlDefinition { SubControlId = "LCK-001.2", SettingName = "Account lockout duration", ExpectedValue = "15 minutes", Description = "How long the account stays locked.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "02", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "LCK-001.3", SettingName = "Reset account lockout counter after", ExpectedValue = "15 minutes", Description = "Time before the failed-attempt counter resets.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "02", EvidenceSources = new() { "net accounts", "secedit" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.GreaterOrEqual }
            }
        },

        // 3. Disable Guest Account (2 SubControls)
        new ControlDefinition
        {
            ControlId = "03", BaselineId = "Hosseini-03", Title = "Disable Guest Account",
            Description = "Removes the built-in Guest account as an attack vector for anonymous access.",
            Category = CheckCategory.Account, Severity = CheckSeverity.Critical, IsBaseline = true,
            TechnicalCheckIds = new() { "GUEST-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "GUEST-001.1", SettingName = "Accounts: Guest account status", ExpectedValue = "Disabled", Description = "Turns off the built-in Guest account.", Category = CheckCategory.Account, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "03", EvidenceSources = new() { "net user", "PowerShell Get-LocalUser", "NetUserGetInfo API" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "GUEST-001.2", SettingName = "Accounts: Rename guest account", ExpectedValue = "Guest", Description = "Makes the well-known account name harder to target. Name must NOT be 'Guest'.", Category = CheckCategory.Account, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "03", EvidenceSources = new() { "PowerShell Get-LocalUser" }, ExpectedValueType = ExpectedValueType.String, Operator = Operator.NotEquals }
            }
        },

        // 4. Advanced Audit Policy Configuration (11 SubControls)
        new ControlDefinition
        {
            ControlId = "04", BaselineId = "Hosseini-04", Title = "Advanced Audit Policy Configuration",
            Description = "Enables granular logging of security-relevant events for monitoring and forensics.",
            Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsBaseline = true,
            TechnicalCheckIds = new() { "AUD-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "AUD-001.1", SettingName = "Audit Logon", ExpectedValue = "Success and Failure", Description = "Logs successful and failed user logons.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol", "Get-WinEvent" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.2", SettingName = "Audit Logoff", ExpectedValue = "Success", Description = "Logs user logoff events.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.3", SettingName = "Audit Special Logon", ExpectedValue = "Success and Failure", Description = "Highlights privileged or special logons.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.4", SettingName = "Audit Credential Validation", ExpectedValue = "Success and Failure", Description = "Logs credential validation on the authenticating system.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.5", SettingName = "Audit User Account Management", ExpectedValue = "Success and Failure", Description = "Logs user account creation, deletion, and modification.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.6", SettingName = "Audit Security Group Management", ExpectedValue = "Success and Failure", Description = "Logs changes to security groups.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.7", SettingName = "Audit Process Creation", ExpectedValue = "Success", Description = "Logs each new process creation event.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.8", SettingName = "Audit Authentication Policy Change", ExpectedValue = "Success and Failure", Description = "Logs changes to authentication policy.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.9", SettingName = "Audit Authorization Policy Change", ExpectedValue = "Success and Failure", Description = "Logs changes to user-rights and authorization policy.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.10", SettingName = "Audit Security State Change", ExpectedValue = "Success and Failure", Description = "Logs startup, shutdown, and security subsystem state changes.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "AUD-001.11", SettingName = "Audit Security System Extension", ExpectedValue = "Success and Failure", Description = "Logs loading of security extensions and related changes.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "04", EvidenceSources = new() { "auditpol" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership }
            }
        },

        // 5. Process Creation Auditing (3 SubControls)
        new ControlDefinition
        {
            ControlId = "05", BaselineId = "Hosseini-05", Title = "Process Creation Auditing",
            Description = "Records every new process together with its full command line for deep forensic visibility.",
            Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsBaseline = true,
            TechnicalCheckIds = new() { "PRC-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "PRC-001.1", SettingName = "Audit Process Creation", ExpectedValue = "Success", Description = "Generates Event ID 4688 for every new process.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "05", EvidenceSources = new() { "auditpol", "Get-WinEvent" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "PRC-001.2", SettingName = "Include command line in process creation events", ExpectedValue = "Enabled", Description = "Adds full command-line arguments to Event ID 4688.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "05", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "PRC-001.3", SettingName = "Force audit policy subcategory settings to override category settings", ExpectedValue = "Enabled", Description = "Prevents basic audit policy from overwriting advanced subcategory settings.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "05", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 6. PowerShell Script Block Logging (3 SubControls)
        new ControlDefinition
        {
            ControlId = "06", BaselineId = "Hosseini-06", Title = "PowerShell Script Block Logging",
            Description = "Captures PowerShell script content and execution context to improve detection of malicious activity.",
            Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsBaseline = true,
            TechnicalCheckIds = new() { "PSH-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "PSH-001.1", SettingName = "Turn on PowerShell Script Block Logging", ExpectedValue = "Enabled", Description = "Logs script block content (Event ID 4104).", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "06", EvidenceSources = new() { "Registry", "PowerShell", "Get-WinEvent" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "PSH-001.2", SettingName = "Turn on Module Logging", ExpectedValue = "Enabled", Description = "Logs pipeline execution details for selected modules.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "06", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "PSH-001.3", SettingName = "Log script block invocation start/stop events", ExpectedValue = "Enabled", Description = "Adds start/stop invocation events for commands and scripts.", Category = CheckCategory.Audit, Severity = CheckSeverity.Medium, IsRequired = false, ParentControlId = "06", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 7. User Rights Assignment (9 SubControls)
        new ControlDefinition
        {
            ControlId = "07", BaselineId = "Hosseini-07", Title = "User Rights Assignment",
            Description = "Controls which users or groups are allowed to perform sensitive system operations.",
            Category = CheckCategory.Account, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "URA-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "URA-001.1", SettingName = "Access this computer from the network", ExpectedValue = "Administrators, Remote Desktop Users", Description = "Restricts network logon to approved groups.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit", "PowerShell" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.2", SettingName = "Deny access to this computer from the network", ExpectedValue = "Guests, Local account", Description = "Blocks risky accounts from network access.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.3", SettingName = "Deny log on as a batch job", ExpectedValue = "Guests", Description = "Prevents Guest accounts from running scheduled or batch jobs.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.4", SettingName = "Deny log on as a service", ExpectedValue = "Guests", Description = "Stops Guest accounts from being used as service identities.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.5", SettingName = "Deny log on locally", ExpectedValue = "Guests", Description = "Blocks Guest interactive console logon.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.6", SettingName = "Deny log on through Remote Desktop Services", ExpectedValue = "Guests, Local account", Description = "Prevents Guests and local accounts from connecting by RDP.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.7", SettingName = "Allow log on through Remote Desktop Services", ExpectedValue = "Administrators, Remote Desktop Users", Description = "Limits RDP access to explicitly approved groups.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.8", SettingName = "Debug programs", ExpectedValue = "Administrators only", Description = "Restricts a dangerous right that allows debugging or attaching to processes.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership },
                new SubControlDefinition { SubControlId = "URA-001.9", SettingName = "Take ownership of files or other objects", ExpectedValue = "Administrators only", Description = "Limits who can seize ownership of protected objects.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "07", EvidenceSources = new() { "secpol.msc", "secedit" }, ExpectedValueType = ExpectedValueType.Collection, Operator = Operator.SetMembership }
            }
        },

        // 8. Security Options (16 SubControls — فاز 11: ADM-001.1/2/3 → SEC-001.6/7/8 + ADM-001.1 جدید)
        new ControlDefinition
        {
            ControlId = "08", BaselineId = "Hosseini-08", Title = "Security Options",
            Description = "Hardens core operating-system security behaviors such as UAC, NTLM, SMB signing, and built-in account handling.",
            Category = CheckCategory.System, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "UAC-001", "LM-001", "ADM-001" },
            SubControls = new()
            {
                // UAC SubControls
                new SubControlDefinition { SubControlId = "UAC-001.1", SettingName = "User Account Control: Run all administrators in Admin Approval Mode", ExpectedValue = "Enabled", Description = "Forces elevation through UAC instead of silent administrator execution.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "UAC-001.2", SettingName = "User Account Control: Behavior of the elevation prompt for administrators", ExpectedValue = "Prompt for consent on the secure desktop", Description = "Moves elevation prompts to the secure desktop.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "UAC-001.3", SettingName = "User Account Control: Detect application installations and prompt for elevation", ExpectedValue = "Enabled", Description = "Detects installer behavior that requires elevation.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                
                // LM SubControls
                new SubControlDefinition { SubControlId = "LM-001.1", SettingName = "Network security: LAN Manager authentication level", ExpectedValue = "Send NTLMv2 response only. Refuse LM & NTLM", Description = "Forces stronger NTLM behavior and blocks weak LM/NTLM.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LM-001.2", SettingName = "Network security: Do not store LAN Manager hash value on next password change", ExpectedValue = "Enabled", Description = "Stops storage of weak LM hashes.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                
                // ═══════════════════════════════════════════════════════════════
                // فاز 11.0: ADM-001.1 جدید (admin count)
                // ═══════════════════════════════════════════════════════════════
                new SubControlDefinition { SubControlId = "ADM-001.1", SettingName = "Local Administrators group member count", ExpectedValue = "2", Description = "Limit local administrator group to essential members only.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "WMI", "PowerShell Get-LocalGroupMember", "net localgroup" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.LessOrEqual },
                
                // SEC SubControls (اصلی)
                new SubControlDefinition { SubControlId = "SEC-001.1", SettingName = "Microsoft network server: Digitally sign communications (always)", ExpectedValue = "Enabled", Description = "Forces SMB server signing.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.2", SettingName = "Microsoft network client: Digitally sign communications (always)", ExpectedValue = "Enabled", Description = "Forces SMB client signing.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.3", SettingName = "Microsoft network client: Send unencrypted password to third-party SMB servers", ExpectedValue = "Disabled", Description = "Prevents plaintext SMB password transmission.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.4", SettingName = "Interactive logon: Don't display last signed-in", ExpectedValue = "Enabled", Description = "Hides the last signed-in user from the sign-in screen.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.5", SettingName = "Interactive logon: Machine inactivity limit", ExpectedValue = "900 seconds (15 minutes)", Description = "Locks inactive sessions automatically.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.LessOrEqual },
                
                // ═══════════════════════════════════════════════════════════════
                // فاز 11.0: انتقال ADM-001.1/2/3 قدیمی به SEC-001.6/7/8
                // ═══════════════════════════════════════════════════════════════
                new SubControlDefinition { SubControlId = "SEC-001.6", SettingName = "Accounts: Limit local account use of blank passwords to console logon only", ExpectedValue = "Enabled", Description = "Stops blank-password local accounts from being used over the network.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.7", SettingName = "Accounts: Administrator account status", ExpectedValue = "Disabled", Description = "Disables the built-in Administrator account when operationally possible.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc", "net user" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SEC-001.8", SettingName = "Accounts: Rename administrator account", ExpectedValue = "Set to a unique non-obvious name", Description = "Reduces exposure of the default Administrator account name.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "08", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.String, Operator = Operator.NotEquals }
            }
        },

        // 9. Disable CMD & Script Execution (3 SubControls)
        new ControlDefinition
        {
            ControlId = "09", BaselineId = "Hosseini-09", Title = "Disable CMD & Script Execution",
            Description = "Blocks standard users from running cmd.exe and batch scripts, reducing attack surface.",
            Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsBaseline = true,
            TechnicalCheckIds = new() { "CMD-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "CMD-001.1", SettingName = "Prevent access to the command prompt", ExpectedValue = "Enabled", Description = "Disables cmd.exe for targeted users.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "09", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CMD-001.2", SettingName = "Disable the command prompt script processing also", ExpectedValue = "Yes", Description = "Blocks .bat and .cmd execution, not only interactive CMD.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "09", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CMD-001.3", SettingName = "Don't run specified Windows applications", ExpectedValue = "Enabled", Description = "Adds a second layer by denying specific executables for non-admin users.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = false, ParentControlId = "09", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 10. Windows Defender Firewall (16 SubControls)
        new ControlDefinition
        {
            ControlId = "10", BaselineId = "Hosseini-10", Title = "Windows Defender Firewall",
            Description = "Ensures the host firewall is enabled on all profiles and blocks inbound connections by default.",
            Category = CheckCategory.Network, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "FW-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "FW-001.1", SettingName = "Domain Profile — Firewall state", ExpectedValue = "On", Description = "Enables firewall protection on domain networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.2", SettingName = "Domain Profile — Inbound connections", ExpectedValue = "Block (default)", Description = "Blocks unsolicited inbound traffic on domain networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.3", SettingName = "Domain Profile — Outbound connections", ExpectedValue = "Allow (default)", Description = "Allows normal outbound traffic.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.4", SettingName = "Private Profile — Firewall state", ExpectedValue = "On", Description = "Enables firewall protection on private networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.5", SettingName = "Private Profile — Inbound connections", ExpectedValue = "Block (default)", Description = "Blocks unsolicited inbound traffic on private networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.6", SettingName = "Public Profile — Firewall state", ExpectedValue = "On", Description = "Enables firewall protection on public networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.7", SettingName = "Public Profile — Inbound connections", ExpectedValue = "Block all", Description = "Applies the strictest inbound posture on public networks.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.8", SettingName = "Domain Profile — Display a notification", ExpectedValue = "No", Description = "Suppresses blocked-program pop-up notifications.", Category = CheckCategory.Network, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.9", SettingName = "Private Profile — Display a notification", ExpectedValue = "No", Description = "Suppresses blocked-program pop-up notifications.", Category = CheckCategory.Network, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.10", SettingName = "Public Profile — Display a notification", ExpectedValue = "No", Description = "Suppresses blocked-program pop-up notifications.", Category = CheckCategory.Network, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.11", SettingName = "Domain Profile — Apply local firewall rules", ExpectedValue = "No", Description = "Ensures only centrally managed firewall rules apply.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.12", SettingName = "Private Profile — Apply local firewall rules", ExpectedValue = "No", Description = "Prevents local administrators from adding unmanaged firewall rules.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.13", SettingName = "Public Profile — Apply local firewall rules", ExpectedValue = "No", Description = "Prevents unmanaged local firewall rule additions.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.14", SettingName = "Domain Profile — Apply local connection security rules", ExpectedValue = "No", Description = "Ensures only centrally defined IPsec/connection security rules apply.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.15", SettingName = "Private Profile — Apply local connection security rules", ExpectedValue = "No", Description = "Prevents local connection-security rule sprawl.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "FW-001.16", SettingName = "Public Profile — Apply local connection security rules", ExpectedValue = "No", Description = "Keeps public-profile connection-security rules centrally controlled.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "10", EvidenceSources = new() { "Registry", "wf.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 11. Disable LLMNR & NetBIOS (7 SubControls)
        new ControlDefinition
        {
            ControlId = "11", BaselineId = "Hosseini-11", Title = "Disable LLMNR & NetBIOS",
            Description = "Disables legacy name-resolution behaviors commonly abused in poisoning and relay attacks.",
            Category = CheckCategory.Network, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "LLN-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "LLN-001.1", SettingName = "Turn off multicast name resolution (LLMNR)", ExpectedValue = "Enabled", Description = "Disables LLMNR and reduces responder-style poisoning opportunities.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "11", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.2", SettingName = "NetBIOS over TCP/IP — preferred central method (DHCP)", ExpectedValue = "0x2 (Disable NetBIOS)", Description = "Uses DHCP to instruct clients to disable NetBIOS over TCP/IP.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "11", EvidenceSources = new() { "DHCP Server Console" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.3", SettingName = "Client-side prerequisite for DHCP-driven NetBIOS control", ExpectedValue = "Use NetBIOS setting from the DHCP server", Description = "Allows the DHCP option above to take effect on the client.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "11", EvidenceSources = new() { "ncpa.cpl", "WMI" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.4", SettingName = "NetBIOS over TCP/IP — fallback local adapter method", ExpectedValue = "Disable NetBIOS over TCP/IP", Description = "Directly disables NetBIOS per adapter when DHCP control is not used.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "11", EvidenceSources = new() { "ncpa.cpl", "Registry" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.5", SettingName = "NetBIOS over TCP/IP — registry deployment method", ExpectedValue = "2", Description = "Registry-based deployment option when you must enforce the setting centrally outside DHCP.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "11", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.6", SettingName = "WPAD (optional hardening) — WinHTTP layer", ExpectedValue = "1", Description = "Disables WPAD discovery for WinHTTP-based proxy auto-discovery.", Category = CheckCategory.Network, Severity = CheckSeverity.Medium, IsRequired = false, ParentControlId = "11", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "LLN-001.7", SettingName = "WPAD (optional hardening) — user/browser layer", ExpectedValue = "Off", Description = "Disables UI/browser-side proxy auto-discovery that may still be used by applications.", Category = CheckCategory.Network, Severity = CheckSeverity.Medium, IsRequired = false, ParentControlId = "11", EvidenceSources = new() { "inetcpl.cpl", "Registry" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 12. Credential Guard & LSA Protection (6 SubControls)
        new ControlDefinition
        {
            ControlId = "12", BaselineId = "Hosseini-12", Title = "Credential Guard & LSA Protection",
            Description = "Uses virtualization-based security and protected LSASS to reduce credential theft from memory.",
            Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsBaseline = true,
            TechnicalCheckIds = new() { "CRG-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "CRG-001.1", SettingName = "Turn On Virtualization Based Security", ExpectedValue = "Enabled", Description = "Turns on the VBS platform required by Credential Guard.", Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "gpedit.msc", "Get-CimInstance" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CRG-001.2", SettingName = "Select Platform Security Level", ExpectedValue = "Secure Boot and DMA Protection", Description = "Raises the underlying hardware-backed trust level.", Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CRG-001.3", SettingName = "Credential Guard Configuration", ExpectedValue = "Enabled with UEFI lock", Description = "Protects LSA secrets and stores the enablement in firmware.", Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CRG-001.4", SettingName = "Secure Launch Configuration", ExpectedValue = "Enabled", Description = "Uses System Guard Secure Launch where supported.", Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CRG-001.5", SettingName = "Configure LSASS to run as a protected process", ExpectedValue = "Enabled with UEFI Lock", Description = "Prevents unprotected processes from loading into LSASS or reading LSASS memory.", Category = CheckCategory.System, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "CRG-001.6", SettingName = "Microsoft network client: Send unencrypted password to third-party SMB servers", ExpectedValue = "Disabled", Description = "Ensures SMB authentication does not fall back to plaintext password transmission.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "12", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 13. Disable SMBv1 (5 SubControls)
        new ControlDefinition
        {
            ControlId = "13", BaselineId = "Hosseini-13", Title = "Disable SMBv1",
            Description = "Removes the legacy SMBv1 protocol and blocks related insecure compatibility fallbacks.",
            Category = CheckCategory.Network, Severity = CheckSeverity.Critical, IsBaseline = true,
            TechnicalCheckIds = new() { "SMB-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "SMB-001.1", SettingName = "Remove SMBv1 Windows feature (PowerShell)", ExpectedValue = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol", Description = "Removes the SMB1 optional feature from the operating system.", Category = CheckCategory.Network, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "13", EvidenceSources = new() { "PowerShell", "DISM" }, ExpectedValueType = ExpectedValueType.String, Operator = Operator.Contains },
                new SubControlDefinition { SubControlId = "SMB-001.2", SettingName = "Disable SMB1 server behavior via registry", ExpectedValue = "0", Description = "Disables SMBv1 on the server side.", Category = CheckCategory.Network, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "13", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SMB-001.3", SettingName = "Allow insecure guest logons", ExpectedValue = "Disabled", Description = "Blocks unauthenticated SMB guest access.", Category = CheckCategory.Network, Severity = CheckSeverity.Critical, IsRequired = true, ParentControlId = "13", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SMB-001.4", SettingName = "Microsoft network client: Digitally sign communications (always)", ExpectedValue = "Enabled", Description = "Requires SMB client signing.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "13", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "SMB-001.5", SettingName = "Microsoft network server: Digitally sign communications (always)", ExpectedValue = "Enabled", Description = "Requires SMB server signing.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "13", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 14. Windows Update / Patch Management (4 SubControls)
        new ControlDefinition
        {
            ControlId = "14", BaselineId = "Hosseini-14", Title = "Windows Update / Patch Management",
            Description = "Manages automatic update behavior for patch management in isolated or WSUS-backed environments.",
            Category = CheckCategory.System, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "WUP-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "WUP-001.1", SettingName = "Configure Automatic Updates", ExpectedValue = "4", Description = "Auto download and schedule the install (AUOptions = 4).", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "14", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "WUP-001.2", SettingName = "Specify intranet Microsoft update service location", ExpectedValue = "http", Description = "Redirects clients to an internal WSUS server (URL contains 'http').", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = false, ParentControlId = "14", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.String, Operator = Operator.Contains },
                new SubControlDefinition { SubControlId = "WUP-001.3", SettingName = "No auto-restart with logged on users", ExpectedValue = "1", Description = "Enabled (NoAutoRebootWithLoggedOnUsers = 1).", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = false, ParentControlId = "14", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "WUP-001.4", SettingName = "Verify latest patches", ExpectedValue = "KB", Description = "Confirms the client has a recent cumulative update installed (KB ID present in Get-HotFix output).", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "14", EvidenceSources = new() { "PowerShell" }, ExpectedValueType = ExpectedValueType.String, Operator = Operator.Contains }
            }
        },

        // 15. Disable Autorun / Autoplay (3 SubControls)
        new ControlDefinition
        {
            ControlId = "15", BaselineId = "Hosseini-15", Title = "Disable Autorun / Autoplay",
            Description = "Stops Windows from auto-executing code on removable media.",
            Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsBaseline = true,
            TechnicalCheckIds = new() { "ARD-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "ARD-001.1", SettingName = "Turn off AutoPlay", ExpectedValue = "Enabled — All drives", Description = "Disables AutoPlay on every drive type.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "15", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "ARD-001.2", SettingName = "Set the default behavior for AutoRun", ExpectedValue = "Enabled — Do not execute any autorun commands", Description = "Prevents automatic execution of autorun.inf actions.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "15", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "ARD-001.3", SettingName = "Disallow Autoplay for non-volume devices", ExpectedValue = "Enabled", Description = "Blocks AutoPlay for MTP/PTP-style devices such as phones and cameras.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "15", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // 16. Secure RDP (7 SubControls)
        new ControlDefinition
        {
            ControlId = "16", BaselineId = "Hosseini-16", Title = "Secure RDP",
            Description = "Hardens Remote Desktop with NLA, stronger encryption, and session limits.",
            Category = CheckCategory.Network, Severity = CheckSeverity.High, IsBaseline = true,
            TechnicalCheckIds = new() { "RDP-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "RDP-001.1", SettingName = "Require user authentication for remote connections by using Network Level Authentication", ExpectedValue = "Enabled", Description = "Requires authentication before a full RDP session is created.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "RDP-001.2", SettingName = "Set client connection encryption level", ExpectedValue = "3", Description = "Enforces stronger RDP session encryption (High = 3).", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "RDP-001.3", SettingName = "Require secure RPC communication", ExpectedValue = "Enabled", Description = "Requires authenticated and encrypted RPC communication.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "RDP-001.4", SettingName = "Always prompt for password upon connection", ExpectedValue = "Enabled", Description = "Forces password entry on each connection.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "RDP-001.5", SettingName = "Limit number of connections", ExpectedValue = "5", Description = "Restricts concurrent sessions to 5 or fewer.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.LessOrEqual },
                new SubControlDefinition { SubControlId = "RDP-001.6", SettingName = "Set time limit for active but idle Remote Desktop Services sessions", ExpectedValue = "15 minutes", Description = "Disconnects idle RDP sessions.", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Duration, Operator = Operator.LessOrEqual },
                new SubControlDefinition { SubControlId = "RDP-001.7", SettingName = "Set time limit for disconnected sessions", ExpectedValue = "60000", Description = "Ends disconnected sessions quickly (max 60 seconds = 60000 ms).", Category = CheckCategory.Network, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "16", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.LessOrEqual }
            }
        },

        // 17. Event Log Size & Retention (13 SubControls)
        new ControlDefinition
        {
            ControlId = "17", BaselineId = "Hosseini-17", Title = "Event Log Size & Retention",
            Description = "Increases log capacity and clarifies where size, retention, and automatic backup options are actually configured.",
            Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsBaseline = true,
            TechnicalCheckIds = new() { "EVL-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "EVL-001.1", SettingName = "Application — Specify the maximum log file size (KB)", ExpectedValue = "65536 KB (64 MB)", Description = "Ensures the Application log retains more history.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc", "wevtutil" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "EVL-001.2", SettingName = "Security — Specify the maximum log file size (KB)", ExpectedValue = "131072 KB (128 MB)", Description = "Gives the Security log more capacity for critical events.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc", "wevtutil" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "EVL-001.3", SettingName = "System — Specify the maximum log file size (KB)", ExpectedValue = "65536 KB (64 MB)", Description = "Ensures the System log retains more history.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc", "wevtutil" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "EVL-001.4", SettingName = "Setup — Specify the maximum log file size (KB)", ExpectedValue = "32768 KB (32 MB)", Description = "Retains setup and servicing events for troubleshooting.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc", "wevtutil" }, ExpectedValueType = ExpectedValueType.Integer, Operator = Operator.GreaterOrEqual },
                new SubControlDefinition { SubControlId = "EVL-001.5", SettingName = "Application retention behavior (legacy label)", ExpectedValue = "Overwrite events as needed", Description = "Legacy path/name found on some policy sets.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.6", SettingName = "Security retention behavior (legacy label)", ExpectedValue = "Overwrite events as needed", Description = "Legacy path/name found on some policy sets.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.7", SettingName = "System retention behavior (legacy label)", ExpectedValue = "Overwrite events as needed", Description = "Legacy path/name found on some policy sets.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "secpol.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.8", SettingName = "Application retention behavior (modern ADMX name)", ExpectedValue = "Overwrite events as needed", Description = "Modern equivalent naming used by newer Administrative Template mappings.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.9", SettingName = "Security retention behavior (modern ADMX name)", ExpectedValue = "Overwrite events as needed", Description = "Modern equivalent naming for Security log retention behavior.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.10", SettingName = "System retention behavior (modern ADMX name)", ExpectedValue = "Overwrite events as needed", Description = "Modern equivalent naming for System log retention behavior.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = true, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Enum, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.11", SettingName = "Application — Back up log automatically when full", ExpectedValue = "Enabled (optional)", Description = "Automatically closes/renames the full log and starts a new one.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.12", SettingName = "Security — Back up log automatically when full", ExpectedValue = "Enabled (optional)", Description = "Creates automatic archival behavior for the Security log.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "EVL-001.13", SettingName = "System — Back up log automatically when full", ExpectedValue = "Enabled (optional)", Description = "Creates automatic archival behavior for the System log.", Category = CheckCategory.Audit, Severity = CheckSeverity.Low, IsRequired = false, ParentControlId = "17", EvidenceSources = new() { "Registry", "gpedit.msc" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },

        // ══════════════════════════════════════════════════════════════
        // EXTENDED CHECKS (Not in PDF baseline, but still scanned)
        // فاز 11.0: پر شدن SubControls برای EXT-01, EXT-02, EXT-03
        // ══════════════════════════════════════════════════════════════
        new ControlDefinition
        {
            ControlId = "EXT-01", BaselineId = "", Title = "Windows Defender",
            Description = "Verifies Windows Defender antivirus is enabled and configured properly.",
            Category = CheckCategory.System, Severity = CheckSeverity.High, IsBaseline = false,
            TechnicalCheckIds = new() { "DEF-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "DEF-001.1", SettingName = "Antivirus enabled", ExpectedValue = "Enabled", Description = "Ensures Windows Defender antivirus is active.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "EXT-01", EvidenceSources = new() { "PowerShell Get-MpComputerStatus" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "DEF-001.2", SettingName = "Real-time protection enabled", ExpectedValue = "Enabled", Description = "Ensures real-time monitoring is active.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "EXT-01", EvidenceSources = new() { "Registry", "PowerShell Get-MpComputerStatus" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals },
                new SubControlDefinition { SubControlId = "DEF-001.3", SettingName = "Antivirus definitions up-to-date", ExpectedValue = "Enabled", Description = "Verifies virus definitions are current.", Category = CheckCategory.System, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "EXT-01", EvidenceSources = new() { "PowerShell Get-MpComputerStatus" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },
        new ControlDefinition
        {
            ControlId = "EXT-02", BaselineId = "", Title = "USB Storage Policy",
            Description = "Restricts USB storage device access to prevent data exfiltration.",
            Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsBaseline = false,
            TechnicalCheckIds = new() { "USB-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "USB-001.1", SettingName = "USB storage device access restricted", ExpectedValue = "Enabled", Description = "Disables USB storage devices via USBSTOR service.", Category = CheckCategory.System, Severity = CheckSeverity.Medium, IsRequired = true, ParentControlId = "EXT-02", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        },
        new ControlDefinition
        {
            ControlId = "EXT-03", BaselineId = "", Title = "AutoLogon Disabled",
            Description = "Ensures automatic logon is disabled to prevent unauthorized access.",
            Category = CheckCategory.Account, Severity = CheckSeverity.High, IsBaseline = false,
            TechnicalCheckIds = new() { "ALG-001" },
            SubControls = new()
            {
                new SubControlDefinition { SubControlId = "ALG-001.1", SettingName = "Automatic logon disabled", ExpectedValue = "Disabled", Description = "Prevents automatic logon with stored credentials.", Category = CheckCategory.Account, Severity = CheckSeverity.High, IsRequired = true, ParentControlId = "EXT-03", EvidenceSources = new() { "Registry", "PowerShell" }, ExpectedValueType = ExpectedValueType.Boolean, Operator = Operator.Equals }
            }
        }
    };

    public static IReadOnlyList<ControlDefinition> GetAll() => _controls.AsReadOnly();

    public static IEnumerable<ControlDefinition> GetBaseline() => _controls.Where(c => c.IsBaseline);

    public static IEnumerable<ControlDefinition> GetExtended() => _controls.Where(c => !c.IsBaseline);

    public static ControlDefinition? GetByCheckId(string checkId)
    {
        return _controls.FirstOrDefault(c => c.TechnicalCheckIds.Contains(checkId));
    }

    public static IEnumerable<Finding> GetFindingsForControl(ControlDefinition control, IEnumerable<Finding> allFindings)
    {
        return allFindings.Where(f => control.TechnicalCheckIds.Contains(f.CheckId));
    }

    public static SubControlDefinition? GetSubControlById(string subControlId)
    {
        foreach (var control in _controls)
        {
            var subControl = control.SubControls.FirstOrDefault(s => s.SubControlId == subControlId);
            if (subControl != null) return subControl;
        }
        return null;
    }
}