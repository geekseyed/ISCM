using System.Text.Json;
using System.Text.Json.Serialization;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Infrastructure.Persistence.Serialization;

/// <summary>
/// Custom JSON converter for <see cref="DurationValue"/>.
/// Ensures Value (long) and Unit (DurationUnit enum) are serialized deterministically.
/// </summary>
public class DurationValueJsonConverter : JsonConverter<DurationValue>
{
    public override DurationValue? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;

        using var doc = JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;

        long value = 0;
        if (root.TryGetProperty("value", out var vProp) || root.TryGetProperty("Value", out vProp))
            value = vProp.GetInt64();

        DurationUnit unit = DurationUnit.Seconds;
        if (root.TryGetProperty("unit", out var uProp) || root.TryGetProperty("Unit", out uProp))
        {
            unit = uProp.ValueKind == JsonValueKind.String
                ? Enum.Parse<DurationUnit>(uProp.GetString()!)
                : (DurationUnit)uProp.GetInt32();
        }

        return new DurationValue(value, unit);
    }

    public override void Write(Utf8JsonWriter writer, DurationValue value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("Value", value.Value);
        writer.WriteString("Unit", value.Unit.ToString());
        writer.WriteEndObject();
    }
}