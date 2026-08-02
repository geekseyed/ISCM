using ISCM.Domain.Common;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Domain.Entities;

public class Asset : BaseEntity
{
    public string Name { get; private set; } = string.Empty;

    public AssetType Type { get; private set; }

    public OperatingSystemInfo OperatingSystem { get; private set; }

    public IPAddressValue IPAddress { get; private set; }

    public string Location { get; private set; } = string.Empty;


    private Asset()
    {
        OperatingSystem = null!;
        IPAddress = null!;
    }


    public Asset(
        string name,
        AssetType type,
        OperatingSystemInfo operatingSystem,
        IPAddressValue ipAddress,
        string location)
    {
        Name = name;
        Type = type;
        OperatingSystem = operatingSystem;
        IPAddress = ipAddress;
        Location = location;
    }
}