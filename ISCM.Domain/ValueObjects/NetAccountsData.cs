namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Structured representation of `net accounts` command output.
/// Each setting is extracted INDIVIDUALLY - the complete command output
/// is NEVER stored as the value of a single setting (BUG-02).
/// </summary>
public class NetAccountsData
{
    /// <summary>
    /// Canonical key -> raw value (for audit and unknown fields)
    /// </summary>
    public Dictionary<string, string> RawSettings { get; } = new(StringComparer.OrdinalIgnoreCase);

    // === TYPED SETTINGS ===

    /// <summary>Raw value, e.g. "Never" or "0"</summary>
    public string? ForceUserLogoffRaw { get; set; }
    public int? ForceUserLogoffMinutes { get; set; }
    public bool ForceUserLogoffNever { get; set; }

    public int? MinimumPasswordAgeDays { get; set; }
    public int? MaximumPasswordAgeDays { get; set; }
    public bool MaximumPasswordAgeUnlimited { get; set; }

    public int? MinimumPasswordLength { get; set; }
    public int? PasswordHistoryLength { get; set; }
    public int? LockoutThreshold { get; set; }
    public bool LockoutDisabled { get; set; }

    public int? LockoutDurationMinutes { get; set; }
    public int? LockoutObservationWindowMinutes { get; set; }
    public string? ComputerRole { get; set; }

    public DateTime ParsedAtUtc { get; } = DateTime.UtcNow;

    // === QUERIES ===

    public string? GetRaw(string canonicalKey)
    {
        return RawSettings.TryGetValue(canonicalKey, out var v) ? v : null;
    }

    public bool HasSetting(string canonicalKey)
    {
        return RawSettings.ContainsKey(canonicalKey);
    }

    public IEnumerable<string> GetSettingNames()
    {
        return RawSettings.Keys;
    }

    public override string ToString()
    {
        return $"NetAccountsData [{RawSettings.Count} settings]";
    }
}