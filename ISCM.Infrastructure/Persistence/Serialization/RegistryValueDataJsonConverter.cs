using System.Text.Json;
using System.Text.Json.Serialization;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Infrastructure.Persistence.Serialization;

/// <summary>
/// Custom JSON converter for <see cref="RegistryValueData"/>.
/// 
/// Handles the nested polymorphic challenge of the `object? Data` property
/// by using the `DataType` (RegistryDataType enum) as a discriminator.
/// </summary>
public class RegistryValueDataJsonConverter : JsonConverter<RegistryValueData>
{
    public override RegistryValueData? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;

        using var doc = JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;

        string keyPath = string.Empty;
        if (root.TryGetProperty("keyPath", out var kProp) || root.TryGetProperty("KeyPath", out kProp))
            keyPath = kProp.GetString() ?? string.Empty;

        string valueName = string.Empty;
        if (root.TryGetProperty("valueName", out var vnProp) || root.TryGetProperty("ValueName", out vnProp))
            valueName = vnProp.GetString() ?? string.Empty;

        RegistryDataType dataType = RegistryDataType.Unknown;
        if (root.TryGetProperty("dataType", out var dtProp) || root.TryGetProperty("DataType", out dtProp))
        {
            dataType = dtProp.ValueKind == JsonValueKind.String
                ? Enum.Parse<RegistryDataType>(dtProp.GetString()!)
                : (RegistryDataType)dtProp.GetInt32();
        }

        object? data = null;
        JsonElement dataProp = default;
        if (root.TryGetProperty("data", out dataProp) || root.TryGetProperty("Data", out dataProp))
        {
            if (dataProp.ValueKind != JsonValueKind.Null)
            {
                var rawText = dataProp.GetRawText();
                data = dataType switch
                {
                    RegistryDataType.String or RegistryDataType.ExpandString => dataProp.GetString(),
                    RegistryDataType.DWord => dataProp.GetInt32(),
                    RegistryDataType.QWord => dataProp.GetInt64(),
                    RegistryDataType.Binary => dataProp.GetBytesFromBase64(),
                    RegistryDataType.MultiString => JsonSerializer.Deserialize<string[]>(rawText, options),
                    _ => JsonSerializer.Deserialize<JsonElement>(rawText, options) // Fallback
                };
            }
        }

        return new RegistryValueData(keyPath, valueName, dataType, data);
    }

    public override void Write(Utf8JsonWriter writer, RegistryValueData value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("KeyPath", value.KeyPath);
        writer.WriteString("ValueName", value.ValueName);
        writer.WriteString("DataType", value.DataType.ToString());

        writer.WritePropertyName("Data");
        if (value.Data == null)
        {
            writer.WriteNullValue();
        }
        else
        {
            // Serialize using actual runtime type (e.g. int, string, byte[])
            JsonSerializer.Serialize(writer, value.Data, value.Data.GetType(), options);
        }

        writer.WriteEndObject();
    }
}