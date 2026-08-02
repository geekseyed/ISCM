using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Application.Features.Assets.DTOs;

namespace ISCM.Application.Features.Assets.Services;

public interface IAssetService
{
    Task<IEnumerable<AssetDto>> GetAllAsync();
}
