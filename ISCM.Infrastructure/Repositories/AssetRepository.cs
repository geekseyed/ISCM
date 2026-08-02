using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;

namespace ISCM.Infrastructure.Repositories;

public class AssetRepository : IAssetRepository
{

    private readonly List<Asset> _assets = new();


    public Task<IEnumerable<Asset>> GetAllAsync()
    {
        return Task.FromResult(
            _assets.AsEnumerable()
        );
    }


    public Task<Asset?> GetByIdAsync(Guid id)
    {
        var asset = _assets
            .FirstOrDefault(x => x.Id == id);

        return Task.FromResult(asset);
    }


    public Task AddAsync(Asset asset)
    {
        _assets.Add(asset);

        return Task.CompletedTask;
    }
}
