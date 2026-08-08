using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ISCM.Domain.Common;

public abstract class BaseEntity
{
    public Guid Id { get; protected init; } = Guid.NewGuid();
    public DateTimeOffset CreatedAtUtc { get; protected init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ModifiedAtUtc { get; protected set; }

    protected void MarkModified()
    {
        ModifiedAtUtc = DateTimeOffset.UtcNow;
    }
}
