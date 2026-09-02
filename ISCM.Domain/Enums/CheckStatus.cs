namespace ISCM.Domain.Enums;

public enum CheckStatus
{
    NotScanned = 0,
    Pass = 1,
    Fail = 2,
    Unknown = 3,
    NotApplicable = 4,
    Error = 5,
    Ignored = 6,
    FalsePositive = 7,
    Unsupported = 8,
    Disagreement = 9
}