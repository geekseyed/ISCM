using System.Text.Json;
using System.Text.Json.Serialization;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Infrastructure.Persistence.Serialization;

/// <summary>
/// Custom JSON converter for <see cref="EvidenceValue"/>.
/// 
/// Phase 13.4: Solves the polymorphic serialization challenge of the `object? TypedValue`
/// property without polluting the Domain layer with [JsonDerivedType] attributes.
/// 
/// Strategy:
/// - Reads the `ValueType` discriminator first
/// - Deserializes `TypedValue` into the correct concrete runtime type based on ValueType
/// - Supports both CamelCase and PascalCase property names for forward/backward compatibility
/// - Handles both string and integer enum representations
/// </summary>
public class EvidenceValueJsonConverter : JsonConverter<EvidenceValue>
{
    public override EvidenceValue? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;

        using var doc = JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;

        // 1. Read ValueType discriminator
        var valueType = EvidenceValueType.Unknown;
        if (root.TryGetProperty("valueType", out var vtProp) || root.TryGetProperty("ValueType", out vtProp))
        {
            valueType = vtProp.ValueKind == JsonValueKind.String
                ? Enum.Parse<EvidenceValueType>(vtProp.GetString()!)
                : (EvidenceValueType)vtProp.GetInt32();
        }

        // 2. Read Unit
        string? unit = null;
        if (root.TryGetProperty("unit", out var uProp) || root.TryGetProperty("Unit", out uProp))
        {
            if (uProp.ValueKind != JsonValueKind.Null) unit = uProp.GetString();
        }

        // 3. Read RawString
        string rawString = string.Empty;
        if (root.TryGetProperty("rawString", out var rProp) || root.TryGetProperty("RawString", out rProp))
        {
            if (rProp.ValueKind != JsonValueKind.Null) rawString = rProp.GetString() ?? string.Empty;
        }

        // 4. Read and dispatch TypedValue based on ValueType
        object? typedValue = null;
        JsonElement typedProp = default;
        bool hasTypedValue = root.TryGetProperty("typedValue", out typedProp) || root.TryGetProperty("TypedValue", out typedProp);

        if (hasTypedValue && typedProp.ValueKind != JsonValueKind.Null)
        {
            var rawText = typedProp.GetRawText();
            typedValue = valueType switch
            {
                EvidenceValueType.String => typedProp.GetString(),
                EvidenceValueType.Integer => typedProp.GetInt32(),
                EvidenceValueType.Long => typedProp.GetInt64(),
                EvidenceValueType.Boolean => typedProp.GetBoolean(),
                EvidenceValueType.DateTime => typedProp.GetDateTime(),
                EvidenceValueType.Duration => JsonSerializer.Deserialize<DurationValue>(rawText, options),
                EvidenceValueType.Size => JsonSerializer.Deserialize<SizeValue>(rawText, options),
                EvidenceValueType.RegistryValue => JsonSerializer.Deserialize<RegistryValueData>(rawText, options),
                EvidenceValueType.Enum => typedProp.ValueKind == JsonValueKind.String ? typedProp.GetString() : typedProp.GetInt32(),
                EvidenceValueType.Collection => JsonSerializer.Deserialize<List<string>>(rawText, options),
                _ => JsonSerializer.Deserialize<JsonElement>(rawText, options) // Fallback for unknown types
            };
        }

        return new EvidenceValue(typedValue, valueType, unit, rawString);
    }

    public override void Write(Utf8JsonWriter writer, EvidenceValue value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        writer.WriteString("ValueType", value.ValueType.ToString());

        if (value.Unit != null)
            writer.WriteString("Unit", value.Unit);
        else
            writer.WriteNull("Unit");

        writer.WriteString("RawString", value.RawString);

        writer.WritePropertyName("TypedValue");
        if (value.TypedValue == null)
        {
            writer.WriteNullValue();
        }
        else
        {
            // Serialize using the actual runtime type to trigger specific converters
            JsonSerializer.Serialize(writer, value.TypedValue, value.TypedValue.GetType(), options);
        }

        writer.WriteEndObject();
    }
}