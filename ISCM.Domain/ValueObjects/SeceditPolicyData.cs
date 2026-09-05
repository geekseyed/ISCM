namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Structured representation of secedit /export INF output.
/// Sections contain key=value policy entries.
/// </summary>
public class SeceditPolicyData
{
    /// <summary>
    /// Section name -> (key -> value)
    /// Example: "System Access" -> { "MinimumPasswordLength" -> "14" }
    /// </summary>
    public Dictionary<string, Dictionary<string, string>> Sections { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string? SourcePath { get; set; }
    public DateTime ParsedAtUtc { get; } = DateTime.UtcNow;

    // === QUERIES ===

    public bool HasSection(string sectionName)
    {
        return !string.IsNullOrWhiteSpace(sectionName) && Sections.ContainsKey(sectionName.Trim());
    }

    public bool HasValue(string sectionName, string key)
    {
        return HasSection(sectionName) && Sections[sectionName.Trim()].ContainsKey(key.Trim());
    }

    public string? GetValue(string sectionName, string key)
    {
        if (!HasValue(sectionName, key)) return null;
        return Sections[sectionName.Trim()][key.Trim()];
    }

    public IReadOnlyDictionary<string, string>? GetSection(string sectionName)
    {
        if (!HasSection(sectionName)) return null;
        return Sections[sectionName.Trim()];
    }

    public IEnumerable<string> GetSectionNames()
    {
        return Sections.Keys;
    }

    public int TotalValueCount => Sections.Values.Sum(s => s.Count);

    // === MUTATION (parser only) ===

    public void AddSection(string sectionName)
    {
        var name = sectionName.Trim();
        if (!Sections.ContainsKey(name))
        {
            Sections[name] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public bool TryAddValue(string sectionName, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(sectionName) || string.IsNullOrWhiteSpace(key))
            return false;

        AddSection(sectionName);
        Sections[sectionName.Trim()][key.Trim()] = value.Trim();
        return true;
    }

    public override string ToString()
    {
        return $"SeceditPolicyData [{Sections.Count} sections, {TotalValueCount} values]";
    }
}