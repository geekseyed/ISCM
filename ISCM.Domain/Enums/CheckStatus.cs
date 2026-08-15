using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ISCM.Domain.Enums;

public enum CheckStatus
{
    NotScanned = 0,
    Pass = 1,
    Fail = 2,
    Warning = 3,
    Ignored = 4,
    Error = 5,
    FalsePositive = 6

}
