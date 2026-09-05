namespace ISCM.Domain.ValueObjects;

/// <summary>
/// A single audit policy subcategory entry.
/// </summary>
public class AuditpolEntry
{
    public string Category { get; set; } = string.Empty;
    public string Subcategory { get; set; } = string.Empty;
    public string SettingRaw { get; set; } = string.Empty;
    public bool AuditSuccess { get; set; }
    public bool AuditFailure { get; set; }

    public override string ToString()
    {
        return $"{Category}/{Subcategory} = {SettingRaw}";
    }
}

/// <summary>
/// Structured representation of `auditpol /get /category:*` output.
/// 
/// Lookup is EXACT-match on normalized subcategory names.
/// Loose substring matching (e.g. Contains("Logon")) is PROHIBITED
/// because it would incorrectly match "Logon" vs "Logoff" (BUG-05).
/// </summary>
public class AuditpolData
{
    /// <summary>
    /// Normalized "Category|Subcategory" -> entry
    /// </summary>
    private readonly Dictionary<string, AuditpolEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public DateTime ParsedAtUtc { get; } = DateTime.UtcNow;

    // === MUTATION (parser only) ===

    public void AddEntry(AuditpolEntry entry)
    {
        var key = MakeKey(entry.Category, entry.Subcategory);
        _entries[key] = entry;
    }

    // === QUERIES (exact match only) ===

    public bool HasSubcategory(string category, string subcategory)
    {
        return _entries.ContainsKey(MakeKey(category, subcategory));
    }

    public AuditpolEntry? GetEntry(string category, string subcategory)
    {
        return _entries.TryGetValue(MakeKey(category, subcategory), out var e) ? e : null;
    }

    public string? GetSetting(string category, string subcategory)
    {
        return GetEntry(category, subcategory)?.SettingRaw;
    }

    public IEnumerable<AuditpolEntry> GetAllEntries()
    {
        return _entries.Values;
    }

    public IEnumerable<AuditpolEntry> GetEntriesInCategory(string category)
    {
        var normalized = NormalizeName(category);
        return _entries.Values.Where(e => NormalizeName(e.Category) == normalized);
    }

    public int EntryCount => _entries.Count;

    // === NORMALIZATION ===

    /// <summary>
    /// Normalize a name for EXACT comparison:
    /// lowercase, trim, collapse internal whitespace.
    /// This makes "Logon" != "Logoff" guaranteed.
    /// </summary>
    public static string NormalizeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return string.Empty;
        var collapsed = string.Join(' ', name.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.ToLowerInvariant();
    }

    private static string MakeKey(string category, string subcategory)
    {
        return $"{NormalizeName(category)}|{NormalizeName(subcategory)}";
    }

    public override string ToString()
    {
        return $"AuditpolData [{EntryCount} entries]";
    }
}