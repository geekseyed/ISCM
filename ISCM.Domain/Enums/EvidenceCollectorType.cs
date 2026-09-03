namespace ISCM.Domain.Enums;

/// <summary>
/// The type of collector that acquired the evidence.
/// </summary>
public enum EvidenceCollectorType
{
    Unknown = 0,
    RegistryCollector = 1,
    SeceditCollector = 2,
    NetAccountsCollector = 3,
    AuditpolCollector = 4,
    PowerShellCollector = 5,
    WmiCollector = 6,
    CimCollector = 7,
    FileCollector = 8,
    ServiceCollector = 9,
    EventLogCollector = 10,
    NetworkCollector = 11,
    GroupPolicyCollector = 12,
    FirewallCollector = 13,
    ScheduledTaskCollector = 14,
    HotFixCollector = 15,
    WindowsUpdateCollector = 16,
    SmbCollector = 17,
    SystemInfoCollector = 18,
    CompositeCollector = 19,
    Other = 99
}