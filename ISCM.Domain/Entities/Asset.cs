using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ISCM.Domain.Entities;

public class Asset
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public string OperatingSystem { get; set; } = string.Empty;

    public string IPAddress { get; set; } = string.Empty;

    public string Location { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}