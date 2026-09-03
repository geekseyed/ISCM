using ISCM.Domain.Enums;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Represents a typed evidence value with unit awareness.
/// </summary>
public class EvidenceValue
{
    public object? TypedValue { get; set; }
    public EvidenceValueType ValueType { get; set; } = EvidenceValueType.Unknown;
    public string? Unit { get; set; }
    public string RawString { get; set; } = string.Empty;

    public EvidenceValue() { }

    public EvidenceValue(object? value, EvidenceValueType type, string? unit = null, string? rawString = null)
    {
        TypedValue = value;
        ValueType = type;
        Unit = unit;
        RawString = rawString ?? value?.ToString() ?? string.Empty;
    }

    public static EvidenceValue FromString(string value)
        => new(value, EvidenceValueType.String, rawString: value);

    public static EvidenceValue FromInteger(int value, string? unit = null)
        => new(value, EvidenceValueType.Integer, unit, value.ToString());

    public static EvidenceValue FromLong(long value, string? unit = null)
        => new(value, EvidenceValueType.Long, unit, value.ToString());

    public static EvidenceValue FromBoolean(bool value)
        => new(value, EvidenceValueType.Boolean, rawString: value.ToString());

    public static EvidenceValue FromDuration(DurationValue duration)
        => new(duration, EvidenceValueType.Duration, duration.Unit.ToString(), duration.ToString());

    public static EvidenceValue FromSize(SizeValue size)
        => new(size, EvidenceValueType.Size, size.Unit.ToString(), size.ToString());

    public override string ToString() => RawString;
}