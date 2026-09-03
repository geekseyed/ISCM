namespace ISCM.Domain.Enums;

/// <summary>
/// Windows Registry data types.
/// </summary>
public enum RegistryDataType
{
    Unknown = 0,
    String = 1,        // REG_SZ
    ExpandString = 2,  // REG_EXPAND_SZ
    Binary = 3,        // REG_BINARY
    DWord = 4,         // REG_DWORD
    MultiString = 5,   // REG_MULTI_SZ
    QWord = 6,         // REG_QWORD
    Link = 7,          // REG_LINK
    ResourceList = 8,  // REG_RESOURCE_LIST
    None = 9           // REG_NONE
}