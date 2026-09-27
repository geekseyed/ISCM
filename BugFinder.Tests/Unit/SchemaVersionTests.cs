using System;
using System.Collections.Generic;
using System.Text.Json;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class SchemaVersionTests
{
    private sealed record SamplePayload(int Number, string Text);

    private readonly SchemaVersionService _service = new();

    private static JsonElement SetText(JsonElement payload, string text)
    {
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload.GetRawText())!;
        dict["Text"] = JsonSerializer.SerializeToElement(text);
        return JsonSerializer.SerializeToElement(dict);
    }

    private static JsonElement MultiplyNumberBy10(JsonElement payload)
    {
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload.GetRawText())!;
        dict["Number"] = JsonSerializer.SerializeToElement(dict["Number"].GetInt32() * 10);
        return JsonSerializer.SerializeToElement(dict);
    }

    private static JsonElement AddFiveToNumber(JsonElement payload)
    {
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload.GetRawText())!;
        dict["Number"] = JsonSerializer.SerializeToElement(dict["Number"].GetInt32() + 5);
        return JsonSerializer.SerializeToElement(dict);
    }

    private static string PatchSchemaVersion(string json, int version) =>
        json.Replace("\"SchemaVersion\": 1", $"\"SchemaVersion\": {version}");

    // Stage 1.3.1 — envelope stamped with current version + family + payload
    [Fact]
    public void Write_EnvelopesCurrentVersionFamilyAndPayload()
    {
        var json = _service.Write(new SamplePayload(7, "x"), SchemaFamily.Evidence);

        json.Should().Contain("\"SchemaVersion\": 1");
        json.Should().Contain("\"Family\": \"Evidence\"");
        json.Should().Contain("\"Payload\"");
    }

    // Stage 1.3.2 — current read
    [Fact]
    public void Read_CurrentVersion_ReturnsPayload()
    {
        var json = _service.Write(new SamplePayload(7, "x"), SchemaFamily.Evidence);

        var result = _service.Read<SamplePayload>(json, SchemaFamily.Evidence);

        result.Status.Should().Be(SchemaReadStatus.Current);
        result.IsUsable.Should().BeTrue();
        result.Payload.Should().Be(new SamplePayload(7, "x"));
        result.DocumentSchemaVersion.Should().Be(1);
        result.Diagnostics.Should().BeEmpty();
    }

    // Stage 1.3.2 — round-trip across families (1.3.3 / 1.3.4 use the same path)
    [Theory]
    [InlineData(SchemaFamily.Evidence)]
    [InlineData(SchemaFamily.History)]
    [InlineData(SchemaFamily.InvestigationReport)]
    public void WriteRead_RoundTrip_PerFamily(SchemaFamily family)
    {
        var json = _service.Write(new SamplePayload(3, family.ToString()), family);

        var result = _service.Read<SamplePayload>(json, family);

        result.IsUsable.Should().BeTrue();
        result.Payload.Should().Be(new SamplePayload(3, family.ToString()));
    }

    // Stage 1.3.6 — newer document rejected explicitly
    [Fact]
    public void Read_NewerVersion_NewerThanReaderExplicit()
    {
        var json = PatchSchemaVersion(
            _service.Write(new SamplePayload(1, "x"), SchemaFamily.Evidence), 99);

        var result = _service.Read<SamplePayload>(json, SchemaFamily.Evidence);

        result.Status.Should().Be(SchemaReadStatus.NewerThanReader);
        result.IsUsable.Should().BeFalse();
        result.Payload.Should().BeNull();
        result.DocumentSchemaVersion.Should().Be(99);
        result.Diagnostics.Should().Contain(d => d.Contains("newer than reader"));
    }

    // Stage 1.3.6 — older without migrator: explicit, NOT empty (anti-KBF-11-004)
    [Fact]
    public void Read_OlderVersion_NoMigrator_RequiresMigrationExplicit()
    {
        var v1Json = _service.Write(new SamplePayload(2, "orig"), SchemaFamily.History);
        var reader = new SchemaVersionService(currentVersionOverride: 2);

        var result = reader.Read<SamplePayload>(v1Json, SchemaFamily.History);

        result.Status.Should().Be(SchemaReadStatus.RequiresMigration);
        result.IsUsable.Should().BeFalse();
        result.Payload.Should().BeNull();
        result.Diagnostics.Should().Contain(d => d.Contains("no migrators registered"));
    }

    // Stage 1.3.7 — older with migrator: Migrated + transformed payload
    [Fact]
    public void Read_OlderVersion_WithMigrator_Migrated()
    {
        var v1Json = _service.Write(new SamplePayload(2, "orig"), SchemaFamily.History);
        var reader = new SchemaVersionService(currentVersionOverride: 2);
        reader.RegisterMigrator(SchemaFamily.History, 1, p => SetText(p, "migrated"));

        var result = reader.Read<SamplePayload>(v1Json, SchemaFamily.History);

        result.Status.Should().Be(SchemaReadStatus.Migrated);
        result.IsUsable.Should().BeTrue();
        result.Payload.Should().Be(new SamplePayload(2, "migrated"));
    }

    // Stage 1.3.7 — multi-step chain applied in order (1→2→3)
    [Fact]
    public void Read_MigrationChain_AppliesInOrder()
    {
        var v1Json = _service.Write(new SamplePayload(2, "chain"), SchemaFamily.Evidence);
        var reader = new SchemaVersionService(currentVersionOverride: 3);
        reader.RegisterMigrator(SchemaFamily.Evidence, 1, MultiplyNumberBy10);
        reader.RegisterMigrator(SchemaFamily.Evidence, 2, AddFiveToNumber);

        var result = reader.Read<SamplePayload>(v1Json, SchemaFamily.Evidence);

        result.Status.Should().Be(SchemaReadStatus.Migrated);
        result.Payload.Should().Be(new SamplePayload(25, "chain")); // (2*10)+5
        result.DocumentSchemaVersion.Should().Be(3);
    }

    // Stage 1.3.6 — malformed JSON is explicit
    [Fact]
    public void Read_MalformedJson_Malformed()
    {
        var result = _service.Read<SamplePayload>("{ not json", SchemaFamily.Evidence);

        result.Status.Should().Be(SchemaReadStatus.Malformed);
        result.IsUsable.Should().BeFalse();
        result.Diagnostics.Should().Contain(d => d.Contains("invalid JSON"));
    }

    // Stage 1.3.6 — family mismatch is explicit (wrong reader for artifact)
    [Fact]
    public void Read_FamilyMismatch_Explicit()
    {
        var json = _service.Write(new SamplePayload(1, "x"), SchemaFamily.Evidence);

        var result = _service.Read<SamplePayload>(json, SchemaFamily.History);

        result.Status.Should().Be(SchemaReadStatus.FamilyMismatch);
        result.IsUsable.Should().BeFalse();
    }

    // Stage 1.3.6 — missing envelope fields are explicit
    [Fact]
    public void Read_MissingEnvelopeFields_Malformed()
    {
        _service.Read<SamplePayload>("{\"SchemaVersion\": 1}", SchemaFamily.Evidence)
            .Status.Should().Be(SchemaReadStatus.Malformed);
        _service.Read<SamplePayload>("{\"Family\": \"Evidence\"}", SchemaFamily.Evidence)
            .Status.Should().Be(SchemaReadStatus.Malformed);
    }

    // Stage 1.3.1 — version 0 / negative are invalid, never "older"
    [Fact]
    public void Read_InvalidVersionValues_Malformed()
    {
        var baseJson = _service.Write(new SamplePayload(1, "x"), SchemaFamily.Evidence);

        _service.Read<SamplePayload>(PatchSchemaVersion(baseJson, 0), SchemaFamily.Evidence)
            .Status.Should().Be(SchemaReadStatus.Malformed);
        _service.Read<SamplePayload>(PatchSchemaVersion(baseJson, -3), SchemaFamily.Evidence)
            .Status.Should().Be(SchemaReadStatus.Malformed);
    }

    // Stage 1.3.6 — payload/type mismatch is explicit
    [Fact]
    public void Read_PayloadTypeMismatch_Malformed()
    {
        var json = _service.Write(new SamplePayload(1, "x"), SchemaFamily.Evidence);

        var result = _service.Read<int>(json, SchemaFamily.Evidence);

        result.Status.Should().Be(SchemaReadStatus.Malformed);
        result.Diagnostics.Should().Contain(d => d.Contains("target type"));
    }

    // Stage 1.3.6 — IsUsable only for Current/Migrated
    [Fact]
    public void IsUsable_OnlyCurrentAndMigrated()
    {
        SchemaReadResult<int> Result(SchemaReadStatus status) =>
            new() { Status = status, Payload = 0 };

        Result(SchemaReadStatus.Current).IsUsable.Should().BeTrue();
        Result(SchemaReadStatus.Migrated).IsUsable.Should().BeTrue();
        Result(SchemaReadStatus.RequiresMigration).IsUsable.Should().BeFalse();
        Result(SchemaReadStatus.NewerThanReader).IsUsable.Should().BeFalse();
        Result(SchemaReadStatus.FamilyMismatch).IsUsable.Should().BeFalse();
        Result(SchemaReadStatus.Malformed).IsUsable.Should().BeFalse();
    }

    // Single Truth — BaselineManifest version derives from CoreSchema (H-01.1 seed)
    [Fact]
    public void BaselineManifest_SchemaVersion_DerivesFromCoreSchema()
    {
        BaselineManifest.CurrentSchemaVersion.Should().Be(CoreSchema.CurrentVersion);
    }

    // Contract violations fail fast
    [Fact]
    public void Service_InvalidConstruction_Throws()
    {
        Action zeroOverride = () => new SchemaVersionService(currentVersionOverride: 0);
        Action nullMigrator = () => new SchemaVersionService()
            .RegisterMigrator(SchemaFamily.Evidence, 1, null!);
        Action zeroFromVersion = () => new SchemaVersionService()
            .RegisterMigrator(SchemaFamily.Evidence, 0, p => p);
        Action emptyJson = () => _service.Read<SamplePayload>("  ", SchemaFamily.Evidence);

        zeroOverride.Should().Throw<ArgumentOutOfRangeException>();
        nullMigrator.Should().Throw<ArgumentNullException>();
        zeroFromVersion.Should().Throw<ArgumentOutOfRangeException>();
        emptyJson.Should().Throw<ArgumentException>();
    }
}