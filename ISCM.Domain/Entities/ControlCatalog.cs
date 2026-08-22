using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Catalog of all parent controls (17 baseline + extended checks).
/// Names match the PDF exactly.
/// </summary>
public static class ControlCatalog
{
    private static readonly List<ControlDefinition> _controls = new()
    {
        // ═══════════════════════════════════════════════════════════════
        // BASELINE CONTROLS (17 items from PDF)
        // ═══════════════════════════════════════════════════════════════
        
        new ControlDefinition
        {
            ControlId = "01",
            BaselineId = "MNDCHI-01",
            Title = "Password Policy",
            Description = "Defines rules for password strength, age, and history to prevent weak or reused credentials.",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "PWD-001" }
        },

        new ControlDefinition
        {
            ControlId = "02",
            BaselineId = "MNDCHI-02",
            Title = "Account Lockout Policy",
            Description = "Locks user accounts after repeated failed logon attempts to mitigate brute-force attacks.",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "LCK-001" }
        },

        new ControlDefinition
        {
            ControlId = "03",
            BaselineId = "MNDCHI-03",
            Title = "Disable Guest Account",
            Description = "Removes the built-in Guest account as an attack vector for anonymous access.",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.Critical,
            IsBaseline = true,
            TechnicalCheckIds = new() { "GUEST-001" }
        },

        new ControlDefinition
        {
            ControlId = "04",
            BaselineId = "MNDCHI-04",
            Title = "Advanced Audit Policy Configuration",
            Description = "Enables granular logging of security-relevant events for monitoring and forensics.",
            Category = CheckCategory.Audit,
            Severity = CheckSeverity.Medium,
            IsBaseline = true,
            TechnicalCheckIds = new() { "AUD-001" }
        },

        new ControlDefinition
        {
            ControlId = "05",
            BaselineId = "MNDCHI-05",
            Title = "Process Creation Auditing",
            Description = "Records every new process together with its full command line for deep forensic visibility.",
            Category = CheckCategory.Audit,
            Severity = CheckSeverity.Medium,
            IsBaseline = true,
            TechnicalCheckIds = new() { "PRC-001" }
        },

        new ControlDefinition
        {
            ControlId = "06",
            BaselineId = "MNDCHI-06",
            Title = "PowerShell Script Block Logging",
            Description = "Captures PowerShell script content and execution context to improve detection of malicious activity.",
            Category = CheckCategory.Audit,
            Severity = CheckSeverity.Medium,
            IsBaseline = true,
            TechnicalCheckIds = new() { "PSH-001" }
        },

        new ControlDefinition
        {
            ControlId = "07",
            BaselineId = "MNDCHI-07",
            Title = "User Rights Assignment",
            Description = "Controls which users or groups are allowed to perform sensitive system operations.",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "URA-001" }
        },

        new ControlDefinition
        {
            ControlId = "08",
            BaselineId = "MNDCHI-08",
            Title = "Security Options",
            Description = "Hardens core operating-system security behaviors such as UAC, NTLM, SMB signing, and built-in account handling.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "UAC-001", "LM-001", "ADM-001" }
        },

        new ControlDefinition
        {
            ControlId = "09",
            BaselineId = "MNDCHI-09",
            Title = "Disable CMD & Script Execution",
            Description = "Blocks standard users from running cmd.exe and batch scripts, reducing attack surface.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.Medium,
            IsBaseline = true,
            TechnicalCheckIds = new() { "CMD-001" }
        },

        new ControlDefinition
        {
            ControlId = "10",
            BaselineId = "MNDCHI-10",
            Title = "Windows Defender Firewall",
            Description = "Ensures the host firewall is enabled on all profiles and blocks inbound connections by default.",
            Category = CheckCategory.Network,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "FW-001" }
        },

        new ControlDefinition
        {
            ControlId = "11",
            BaselineId = "MNDCHI-11",
            Title = "Disable LLMNR & NetBIOS",
            Description = "Disables legacy name-resolution behaviors commonly abused in poisoning and relay attacks.",
            Category = CheckCategory.Network,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "LLN-001" }
        },

        new ControlDefinition
        {
            ControlId = "12",
            BaselineId = "MNDCHI-12",
            Title = "Credential Guard & LSA Protection",
            Description = "Uses virtualization-based security and protected LSASS to reduce credential theft from memory.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.Critical,
            IsBaseline = true,
            TechnicalCheckIds = new() { "CRG-001" }
        },

        new ControlDefinition
        {
            ControlId = "13",
            BaselineId = "MNDCHI-13",
            Title = "Disable SMBv1",
            Description = "Removes the legacy SMBv1 protocol and blocks related insecure compatibility fallbacks.",
            Category = CheckCategory.Network,
            Severity = CheckSeverity.Critical,
            IsBaseline = true,
            TechnicalCheckIds = new() { "SMB-001" }
        },

        new ControlDefinition
        {
            ControlId = "14",
            BaselineId = "MNDCHI-14",
            Title = "Windows Update / Patch Management",
            Description = "Manages automatic update behavior for patch management in various network environments.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "WUP-001" }
        },

        new ControlDefinition
        {
            ControlId = "15",
            BaselineId = "MNDCHI-15",
            Title = "Disable Autorun / Autoplay",
            Description = "Stops Windows from auto-executing code on USB drives, CDs, and other removable media.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.Medium,
            IsBaseline = true,
            TechnicalCheckIds = new() { "ARD-001" }
        },

        new ControlDefinition
        {
            ControlId = "16",
            BaselineId = "MNDCHI-16",
            Title = "Secure RDP",
            Description = "Hardens Remote Desktop with NLA, stronger encryption, and session limits.",
            Category = CheckCategory.Network,
            Severity = CheckSeverity.High,
            IsBaseline = true,
            TechnicalCheckIds = new() { "RDP-001" }
        },

        new ControlDefinition
        {
            ControlId = "17",
            BaselineId = "MNDCHI-17",
            Title = "Event Log Size & Retention",
            Description = "Increases log capacity and clarifies where size, retention, and automatic backup options are configured.",
            Category = CheckCategory.Audit,
            Severity = CheckSeverity.Low,
            IsBaseline = true,
            TechnicalCheckIds = new() { "EVL-001" }
        },
        
        // ═══════════════════════════════════════════════════════════════
        // EXTENDED CHECKS (not in PDF baseline, but still scanned)
        // ═══════════════════════════════════════════════════════════════
        
        new ControlDefinition
        {
            ControlId = "EXT-01",
            BaselineId = "",
            Title = "Windows Defender",
            Description = "Verifies Windows Defender antivirus is enabled and configured.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.High,
            IsBaseline = false,
            TechnicalCheckIds = new() { "DEF-001" }
        },

        new ControlDefinition
        {
            ControlId = "EXT-02",
            BaselineId = "",
            Title = "USB Storage Policy",
            Description = "Restricts USB storage device access to prevent data exfiltration.",
            Category = CheckCategory.System,
            Severity = CheckSeverity.Medium,
            IsBaseline = false,
            TechnicalCheckIds = new() { "USB-001" }
        },

        new ControlDefinition
        {
            ControlId = "EXT-03",
            BaselineId = "",
            Title = "AutoLogon Disabled",
            Description = "Ensures automatic logon is disabled to prevent unauthorized access.",
            Category = CheckCategory.Account,
            Severity = CheckSeverity.High,
            IsBaseline = false,
            TechnicalCheckIds = new() { "ALG-001" }
        }
    };

    /// <summary>
    /// Get all control definitions (baseline + extended).
    /// </summary>
    public static IReadOnlyList<ControlDefinition> GetAll() => _controls.AsReadOnly();

    /// <summary>
    /// Get only baseline controls (17 items from PDF).
    /// </summary>
    public static IEnumerable<ControlDefinition> GetBaseline() => _controls.Where(c => c.IsBaseline);

    /// <summary>
    /// Get only extended checks (not in PDF baseline).
    /// </summary>
    public static IEnumerable<ControlDefinition> GetExtended() => _controls.Where(c => !c.IsBaseline);

    /// <summary>
    /// Find the parent control that contains a specific technical check ID.
    /// </summary>
    public static ControlDefinition? GetByCheckId(string checkId)
    {
        return _controls.FirstOrDefault(c => c.TechnicalCheckIds.Contains(checkId));
    }

    /// <summary>
    /// Get all findings that belong to a specific parent control.
    /// </summary>
    public static IEnumerable<Finding> GetFindingsForControl(ControlDefinition control, IEnumerable<Finding> allFindings)
    {
        return allFindings.Where(f => control.TechnicalCheckIds.Contains(f.CheckId));
    }
}