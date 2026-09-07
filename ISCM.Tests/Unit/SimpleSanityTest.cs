using Xunit;
using FluentAssertions;
using ISCM.Domain.Enums;
using ISCM.Domain.Entities;
using ISCM.Domain.ValueObjects;

namespace ISCM.Tests.Unit;

/// <summary>
/// تست سلامت: تأیید اتصال پروژه تست به پروژه‌های اصلی
/// </summary>
public class SimpleSanityTest
{
    [Fact]
    public void Domain_Entities_CanBeInstantiated()
    {
        var evidence = new Evidence { EvidenceId = "test-1", RawOutput = "test output" };
        evidence.Should().NotBeNull();
        evidence.EvidenceId.Should().Be("test-1");
    }

    [Fact]
    public void Domain_Enums_AreAccessible()
    {
        CheckStatus.Pass.Should().Be(CheckStatus.Pass);
    }

    [Fact]
    public void Domain_ValueObjects_CanBeCreated()
    {
        var value = EvidenceValue.FromString("test");
        value.Should().NotBeNull();
    }
}