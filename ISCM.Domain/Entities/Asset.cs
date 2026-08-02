using ISCM.Domain.Common;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

public class Asset : BaseEntity
{
    public string Name { get; private set; } = string.Empty;

    public AssetType Type { get; private set; }

    public string OperatingSystem { get; private set; } = string.Empty;

    public string IPAddress { get; private set; } = string.Empty;

    public string Location { get; private set; } = string.Empty;


    private Asset()
    {
    }


    public Asset(
        string name,
        AssetType type,
        string operatingSystem,
        string ipAddress,
        string location)
    {
        Name = name;
        Type = type;
        OperatingSystem = operatingSystem;
        IPAddress = ipAddress;
        Location = location;
    }
}