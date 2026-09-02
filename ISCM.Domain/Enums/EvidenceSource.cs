namespace ISCM.Domain.Enums;

public enum EvidenceSource
{
    Unknown = 0,
    Registry = 1,
    PowerShell = 2,
    Secedit = 3,
    NetAccounts = 4,
    Auditpol = 5,
    WMI = 6,
    File = 7,
    Service = 8,
    Firewall = 9,
    ScheduledTask = 10,
    EventLog = 11,
    GroupPolicy = 12
}