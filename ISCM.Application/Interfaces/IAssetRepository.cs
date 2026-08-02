using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IAssetRepository
{
    Task<IEnumerable<Asset>> GetAllAsync();

    Task<Asset?> GetByIdAsync(Guid id);

    Task AddAsync(Asset asset);
}
