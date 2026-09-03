using ISCM.Domain.Enums;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Represents a Windows Registry value with full context.
/// </summary>
public class RegistryValueData
{
    public string KeyPath { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public RegistryDataType DataType { get; set; } = RegistryDataType.Unknown;
    public object? Data { get; set; }

    public RegistryValueData() { }

    public RegistryValueData(string keyPath, string valueName, RegistryDataType dataType, object? data)
    {
        KeyPath = keyPath;
        ValueName = valueName;
        DataType = dataType;
        Data = data;
    }

    public string GetFullValuePath() => $@"{KeyPath}\{ValueName}";

    public override string ToString() => $@"{KeyPath}\{ValueName} = {Data} ({DataType})";
}