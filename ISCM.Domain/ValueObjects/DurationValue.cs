using ISCM.Domain.Enums;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Represents a duration value with unit.
/// </summary>
public class DurationValue
{
    public long Value { get; set; }
    public DurationUnit Unit { get; set; }

    public DurationValue() { }

    public DurationValue(long value, DurationUnit unit)
    {
        Value = value;
        Unit = unit;
    }

    public double ToSeconds() => Unit switch
    {
        DurationUnit.Seconds => Value,
        DurationUnit.Minutes => Value * 60,
        DurationUnit.Hours => Value * 3600,
        DurationUnit.Days => Value * 86400,
        DurationUnit.Weeks => Value * 604800,
        DurationUnit.Months => Value * 2592000,  // 30 days approximation
        DurationUnit.Years => Value * 31536000,  // 365 days approximation
        _ => Value
    };

    public double ToMinutes() => ToSeconds() / 60;
    public double ToHours() => ToSeconds() / 3600;
    public double ToDays() => ToSeconds() / 86400;

    public static DurationValue FromDays(long days) => new(days, DurationUnit.Days);
    public static DurationValue FromHours(long hours) => new(hours, DurationUnit.Hours);
    public static DurationValue FromMinutes(long minutes) => new(minutes, DurationUnit.Minutes);
    public static DurationValue FromSeconds(long seconds) => new(seconds, DurationUnit.Seconds);

    public override string ToString() => $"{Value} {Unit}";
}