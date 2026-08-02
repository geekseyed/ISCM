using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Domain.Enums;

namespace ISCM.Application.Features.Assets.DTOs;

public class AssetDto
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public AssetType Type { get; set; }

    public string OperatingSystem { get; set; } = string.Empty;

    public string IPAddress { get; set; } = string.Empty;

    public string Location { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}
