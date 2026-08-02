using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ISCM.Domain.Enums;

public enum AssetType
{
    Unknown = 0,

    Workstation = 1,

    Server = 2,

    VirtualMachine = 3,

    RTU = 4,

    Switch = 5,

    Router = 6,

    Firewall = 7,

    SCADAServer = 8,

    DatabaseServer = 9
}