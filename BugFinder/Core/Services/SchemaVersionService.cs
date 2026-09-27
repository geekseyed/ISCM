using System;
using System.Collections.Generic;
using System.Text.Json;
using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-01.3: Schema Version Service.
/// Write: wraps any payload into the versioned envelope stamped with the
///        current schema version (stages 1.3.2-1.3.4).
/// Read:  parses the envelope and returns an explicit status - Current,
///        Migrated (chain applied), RequiresMigration, NewerThanReader,
///        FamilyMismatch or Malformed - never a fabricated empty state
///        (stage 1.3.6; anti-KBF-11-004). A successful migration is
///        reported as Migrated, never silently as Current (H-01.3.7).
/// RegisterMigrator: migration policy (stage 1.3.7) - per family, from
///        version N to N+1; the reader applies registered steps in order.
/// currentVersionOverride exists ONLY so tests can exercise older/newer
///        paths deterministically; production uses the default binding
///        to CoreSchema.CurrentVersion.
/// </summary>
public class SchemaVersionService
{
    private readonly int _currentVersion;
    private readonly Dictionary<SchemaFamily, Dictionary<int, Func<JsonElement, JsonElement>>> _migrators = new();

    public int CurrentVersion => _currentVersion;

    public SchemaVersionService(int? currentVersionOverride = null)
    {
        if (currentVersionOverride is { } v && v < 1)
            throw new ArgumentOutOfRangeException(nameof(currentVersionOverride),
                "Schema version must be >= 1.");
        _currentVersion = currentVersionOverride ?? CoreSchema.CurrentVersion;
    }

    /// <summary>Register a payload transform vN -> v(N+1) for a family.</summary>
    public void RegisterMigrator(SchemaFamily family, int fromVersion, Func<JsonElement, JsonElement> migrator)
    {
        if (fromVersion < 1)
            throw new ArgumentOutOfRangeException(nameof(fromVersion), "From-version must be >= 1.");
        if (migrator is null) throw new ArgumentNullException(nameof(migrator));

        if (!_migrators.TryGetValue(family, out var steps))
            _migrators[family] = steps = new Dictionary<int, Func<JsonElement, JsonElement>>();
        steps[fromVersion] = migrator;
    }

    /// <summary>Write: envelope with the CURRENT schema version + family + payload.</summary>
    public string Write<T>(T payload, SchemaFamily family)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));

        var envelope = new SchemaEnvelope
        {
            SchemaVersion = _currentVersion,
            Family = family.ToString(),
            Payload = JsonSerializer.SerializeToElement(payload)
        };
        return JsonSerializer.Serialize(envelope, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Read: explicit-status parse; never fabricates an empty payload.</summary>
    public SchemaReadResult<T> Read<T>(string json, SchemaFamily family)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("Envelope JSON is required.", nameof(json));

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            return Fail<T>(SchemaReadStatus.Malformed, $"invalid JSON: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Fail<T>(SchemaReadStatus.Malformed, "envelope root must be a JSON object");

            if (!root.TryGetProperty("SchemaVersion", out var versionElement)
                || !versionElement.TryGetInt32(out var version))
                return Fail<T>(SchemaReadStatus.Malformed, "missing or invalid SchemaVersion");

            if (version <= 0)
                return Fail<T>(SchemaReadStatus.Malformed, $"invalid schema version: {version}");

            if (!root.TryGetProperty("Family", out var familyElement)
                || !Enum.TryParse<SchemaFamily>(familyElement.GetString(), out var documentFamily))
                return Fail<T>(SchemaReadStatus.Malformed, "missing or invalid Family");

            if (documentFamily != family)
                return Fail<T>(SchemaReadStatus.FamilyMismatch,
                    $"envelope family '{documentFamily}' does not match reader family '{family}'");

            if (!root.TryGetProperty("Payload", out var payload)
                || payload.ValueKind == JsonValueKind.Null)
                return Fail<T>(SchemaReadStatus.Malformed, "missing or null Payload");

            if (version > _currentVersion)
                return Fail<T>(SchemaReadStatus.NewerThanReader,
                    $"document schema v{version} is newer than reader v{_currentVersion}", version);

            var element = payload;
            var migrated = false;

            if (version < _currentVersion)
            {
                if (!_migrators.TryGetValue(family, out var steps))
                    return Fail<T>(SchemaReadStatus.RequiresMigration,
                        $"no migrators registered for family '{family}'", version);

                while (version < _currentVersion)
                {
                    if (!steps.TryGetValue(version, out var step))
                        return Fail<T>(SchemaReadStatus.RequiresMigration,
                            $"missing migration step {family} v{version} -> v{version + 1}", version);

                    try
                    {
                        element = step(element);
                    }
                    catch (Exception ex) when (ex is JsonException or InvalidOperationException)
                    {
                        return Fail<T>(SchemaReadStatus.Malformed,
                            $"migration step {family} v{version} -> v{version + 1} failed: {ex.Message}", version);
                    }
                    version++;
                }
                migrated = true;
            }

            try
            {
                var result = element.Deserialize<T>();
                return new SchemaReadResult<T>
                {
                    Status = migrated ? SchemaReadStatus.Migrated : SchemaReadStatus.Current,
                    Payload = result,
                    DocumentSchemaVersion = version
                };
            }
            catch (JsonException ex)
            {
                return Fail<T>(SchemaReadStatus.Malformed,
                    $"payload does not match target type: {ex.Message}", version);
            }
        }
    }

    private static SchemaReadResult<T> Fail<T>(SchemaReadStatus status, string diagnostic, int version = 0) =>
        new()
        {
            Status = status,
            Diagnostics = new[] { diagnostic },
            DocumentSchemaVersion = version
        };
}