using System.Text.Json;
using FluentAssertions;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using ISCM.Infrastructure.Persistence.Serialization;
using Xunit;

namespace ISCM.Tests.Persistence;

/// <summary>
/// Phase 13.8: Verifies polymorphic JSON serialization round-trip for EvidenceValue.
/// </summary>
public class EvidenceValueSerializationTests
{
    [Fact]
    public void EvidenceValue_Boolean_RoundTrip()
    {
        var original = EvidenceValue.FromBoolean(true);
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.Boolean);
        restored.TypedValue.Should().Be(true);
    }

    [Fact]
    public void EvidenceValue_Integer_RoundTrip()
    {
        var original = EvidenceValue.FromInteger(42, "bytes");
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.Integer);
        restored.TypedValue.Should().Be(42);
        restored.Unit.Should().Be("bytes");
    }

    [Fact]
    public void EvidenceValue_String_RoundTrip()
    {
        var original = EvidenceValue.FromString("HKLM\\SOFTWARE\\Test");
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.String);
        restored.TypedValue.Should().Be("HKLM\\SOFTWARE\\Test");
    }

    [Fact]
    public void EvidenceValue_Duration_RoundTrip()
    {
        var duration = new DurationValue(30, DurationUnit.Minutes);
        var original = EvidenceValue.FromDuration(duration);
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.Duration);
        var restoredDuration = restored.TypedValue.Should().BeOfType<DurationValue>().Subject;
        restoredDuration.Value.Should().Be(30);
        restoredDuration.Unit.Should().Be(DurationUnit.Minutes);
    }

    [Fact]
    public void EvidenceValue_Size_RoundTrip()
    {
        var size = new SizeValue(1024, SizeUnit.Megabytes);
        var original = EvidenceValue.FromSize(size);
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.Size);
        var restoredSize = restored.TypedValue.Should().BeOfType<SizeValue>().Subject;
        restoredSize.Value.Should().Be(1024);
        restoredSize.Unit.Should().Be(SizeUnit.Megabytes);
    }

    [Fact]
    public void EvidenceValue_RegistryValue_RoundTrip()
    {
        var regData = new RegistryValueData(
            @"HKLM\SOFTWARE\Test",
            "TestValue",
            RegistryDataType.DWord,
            1);
        var original = new EvidenceValue(regData, EvidenceValueType.RegistryValue);
        var json = JsonSerializer.Serialize(original, DefenDoorJsonOptions.Default);
        var restored = JsonSerializer.Deserialize<EvidenceValue>(json, DefenDoorJsonOptions.Default);

        restored.Should().NotBeNull();
        restored!.ValueType.Should().Be(EvidenceValueType.RegistryValue);
        var restoredReg = restored.TypedValue.Should().BeOfType<RegistryValueData>().Subject;
        restoredReg.KeyPath.Should().Be(@"HKLM\SOFTWARE\Test");
        restoredReg.ValueName.Should().Be("TestValue");
        restoredReg.DataType.Should().Be(RegistryDataType.DWord);
        restoredReg.Data.Should().Be(1);
    }
}