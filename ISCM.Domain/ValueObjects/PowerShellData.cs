namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Type of PowerShell output detected.
/// </summary>
public enum PowerShellOutputType
{
    Unknown = 0,
    Boolean = 1,
    Integer = 2,
    Long = 3,
    String = 4,
    Json = 5,
    MultiLine = 6,
    Array = 7
}

/// <summary>
/// Structured representation of PowerShell command output.
/// </summary>
public class PowerShellData
{
    public PowerShellOutputType OutputType { get; set; } = PowerShellOutputType.Unknown;
    public string RawOutput { get; set; } = string.Empty;

    // === TYPED VALUES ===

    public bool? BooleanValue { get; set; }
    public int? IntegerValue { get; set; }
    public long? LongValue { get; set; }
    public string? StringValue { get; set; }

    /// <summary>
    /// For JSON output: key -> value pairs
    /// </summary>
    public Dictionary<string, string> JsonProperties { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// For MultiLine output: each non-empty line
    /// </summary>
    public List<string> Lines { get; } = new();

    /// <summary>
    /// For Array output: items (e.g., from @() or array literal)
    /// </summary>
    public List<string> ArrayItems { get; } = new();

    public DateTime ParsedAtUtc { get; } = DateTime.UtcNow;

    // === QUERIES ===

    public bool IsBoolean => OutputType == PowerShellOutputType.Boolean;
    public bool IsNumeric => OutputType == PowerShellOutputType.Integer || OutputType == PowerShellOutputType.Long;
    public bool IsJson => OutputType == PowerShellOutputType.Json;
    public bool IsMultiLine => OutputType == PowerShellOutputType.MultiLine;
    public bool IsArray => OutputType == PowerShellOutputType.Array;

    public string? GetJsonProperty(string key)
    {
        return JsonProperties.TryGetValue(key, out var v) ? v : null;
    }

    public bool HasJsonProperty(string key)
    {
        return JsonProperties.ContainsKey(key);
    }

    public string GetStringValue()
    {
        return OutputType switch
        {
            PowerShellOutputType.Boolean => BooleanValue?.ToString() ?? string.Empty,
            PowerShellOutputType.Integer => IntegerValue?.ToString() ?? string.Empty,
            PowerShellOutputType.Long => LongValue?.ToString() ?? string.Empty,
            PowerShellOutputType.String => StringValue ?? string.Empty,
            PowerShellOutputType.MultiLine => string.Join(Environment.NewLine, Lines),
            PowerShellOutputType.Array => string.Join(", ", ArrayItems),
            PowerShellOutputType.Json => RawOutput,
            _ => RawOutput
        };
    }

    public override string ToString()
    {
        return $"PowerShellData [{OutputType}]: {GetStringValue()}";
    }
}