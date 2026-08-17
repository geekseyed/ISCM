using System.Collections.Generic;
using System.Linq;

namespace ISCM.Domain.Entities;

public static partial class GuidanceCatalog
{
    private static List<SubCheck>? _all;

    // همیشه قبل از اولین استفاده، لیست را می‌سازد (ترتیب‌امن)
    private static List<SubCheck> All => _all ??= new List<SubCheck>();

    private static bool Register(params SubCheck[] subs)
    {
        All.AddRange(subs);
        return true;
    }

    // زیرمجموعه‌های یک چک (fallback برای چک‌هایی که SubChecks داخلی ندارند)
    public static IReadOnlyList<SubCheck> Get(string checkId) =>
        All.Where(s => s.Id.StartsWith(checkId + ".")).ToList();
}