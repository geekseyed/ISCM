using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces;

public interface IScanService
{
    Task<ScanResult> RunScanAsync(ScanMode mode = ScanMode.Full);
}
