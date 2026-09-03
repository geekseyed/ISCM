namespace ISCM.Domain.Enums;

/// <summary>
/// The source from which evidence was acquired.
/// </summary>
public enum EvidenceSourceType
{
    Unknown = 0,
    Registry = 1,
    Secedit = 2,
    NetAccounts = 3,
    Auditpol = 4,
    PowerShell = 5,
    Wmi = 6,
    Cim = 7,
    File = 8,
    Service = 9,
    EventLog = 10,
    NetworkApi = 11,
    GroupPolicy = 12,
    FirewallApi = 13,
    ScheduledTask = 14,
    HotFix = 15,
    WindowsUpdate = 16,
    Smb = 17,
    CredentialGuard = 18,
    DeviceGuard = 19,
    Dns = 20,
    Kernel = 21,
    Lsa = 22,
    Browser = 23,
    Cryptography = 24,
    Other = 99
}