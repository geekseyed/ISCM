using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ISCM.Domain.ValueObjects;

public class OperatingSystemInfo
{
    public string Name { get; private set; }

    public string Version { get; private set; }


    private OperatingSystemInfo()
    {
        Name = string.Empty;
        Version = string.Empty;
    }


    public OperatingSystemInfo(
        string name,
        string version)
    {
        Name = name;
        Version = version;
    }


    public override string ToString()
    {
        return $"{Name} {Version}";
    }
}