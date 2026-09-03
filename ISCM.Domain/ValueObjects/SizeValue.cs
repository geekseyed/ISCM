using ISCM.Domain.Enums;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Represents a size value with unit.
/// </summary>
public class SizeValue
{
    public long Value { get; set; }
    public SizeUnit Unit { get; set; }

    public SizeValue() { }

    public SizeValue(long value, SizeUnit unit)
    {
        Value = value;
        Unit = unit;
    }

    public long ToBytes() => Unit switch
    {
        SizeUnit.Bytes => Value,
        SizeUnit.Kilobytes => Value * 1024,
        SizeUnit.Megabytes => Value * 1024 * 1024,
        SizeUnit.Gigabytes => Value * 1024 * 1024 * 1024,
        SizeUnit.Terabytes => Value * 1024L * 1024L * 1024L * 1024L,
        _ => Value
    };

    public double ToKilobytes() => ToBytes() / 1024.0;
    public double ToMegabytes() => ToBytes() / (1024.0 * 1024.0);
    public double ToGigabytes() => ToBytes() / (1024.0 * 1024.0 * 1024.0);

    public static SizeValue FromBytes(long bytes) => new(bytes, SizeUnit.Bytes);
    public static SizeValue FromKilobytes(long kb) => new(kb, SizeUnit.Kilobytes);
    public static SizeValue FromMegabytes(long mb) => new(mb, SizeUnit.Megabytes);
    public static SizeValue FromGigabytes(long gb) => new(gb, SizeUnit.Gigabytes);

    public override string ToString() => $"{Value} {Unit}";
}