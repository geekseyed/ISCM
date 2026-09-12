using System.Text.Json;
using System.Text.Json.Serialization;

namespace ISCM.Infrastructure.Persistence.Serialization;

/// <summary>
/// Centralized JSON serialization options for DefenDoor persistence.
/// 
/// Phase 13.4: Registers all custom converters required to handle polymorphic
/// Domain ValueObjects safely and deterministically.
/// 
/// Usage:
/// - Use <see cref="Default"/> for all persistence serialization/deserialization
/// - Do NOT create new JsonSerializerOptions instances in Repository/Mapper code
/// - Ensures consistent enum handling, casing, and null behavior across the system
/// </summary>
public static class DefenDoorJsonOptions
{
    private static JsonSerializerOptions? _defaultOptions;
    private static readonly object _lock = new();

    public static JsonSerializerOptions Default
    {
        get
        {
            if (_defaultOptions == null)
            {
                lock (_lock)
                {
                    if (_defaultOptions == null)
                    {
                        var options = new JsonSerializerOptions
                        {
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                            PropertyNameCaseInsensitive = true,
                            WriteIndented = false,
                            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                        };

                        // Register custom converters for polymorphic/complex ValueObjects
                        options.Converters.Add(new EvidenceValueJsonConverter());
                        options.Converters.Add(new DurationValueJsonConverter());
                        options.Converters.Add(new SizeValueJsonConverter());
                        options.Converters.Add(new RegistryValueDataJsonConverter());

                        // Handle all other enums as strings for readability and schema stability
                        options.Converters.Add(new JsonStringEnumConverter());

                        _defaultOptions = options;
                    }
                }
            }
            return _defaultOptions;
        }
    }
}