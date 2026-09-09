using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

public class UsbStorageCheckRealSystemTests
{
    [Fact]
    public async Task UsbStorageCheck_RealSystem_ProducesValidFindings()
    {
        var check = new UsbStorageCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(1);

        var evidence = evidenceList.First();
        evidence.SubControlId.Should().Be("USB-001.1");
        evidence.Evaluation.Should().Be(CheckStatus.NotScanned);
        evidence.TypedValue.Should().NotBeNull();
        evidence.TypedValue!.ValueType.Should().Be(EvidenceValueType.Boolean);
    }

    [Fact]
    public async Task UsbStorageCheck_RealSystem_RegistrySource()
    {
        var check = new UsbStorageCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        var evidence = evidenceList.First();
        evidence.SourceType.Should().Be(EvidenceSourceType.Registry);
        evidence.RawOutput.Should().Contain("USBSTOR");
    }
}