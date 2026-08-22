namespace ISCM.Domain.Enums;

public enum CheckStatus
{
    NotScanned,
    Pass,
    Fail,
    Warning,
    Error,
    Ignored,
    FalsePositive,
    Unknown  // NEW: Evidence unavailable (not a security failure)
}