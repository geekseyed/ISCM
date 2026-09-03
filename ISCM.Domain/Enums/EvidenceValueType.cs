namespace ISCM.Domain.Enums;

/// <summary>
/// The semantic data type of an evidence value.
/// </summary>
public enum EvidenceValueType
{
    Unknown = 0,
    String = 1,
    Integer = 2,
    Long = 3,
    Boolean = 4,
    Enum = 5,
    Duration = 6,
    Size = 7,
    RegistryValue = 8,
    PolicyValue = 9,
    StructuredObject = 10,
    Collection = 11,
    DateTime = 12,
    Version = 13
}