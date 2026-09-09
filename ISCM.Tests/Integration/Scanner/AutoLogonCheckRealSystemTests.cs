using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

public class AutoLogonCheckRealSystemTests
{
    [Fact]
    public async Task AutoLogonCheck_RealSystem_ProducesValidFindings()
    {
        var check = new AutoLogonCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCountGreaterThanOrEqualTo(1);

        var evidence = evidenceList.First();
        evidence.SubControlId.Should().Be("ALG-001.1");
        evidence.Evaluation.Should().Be(CheckStatus.NotScanned);
        evidence.TypedValue.Should().NotBeNull();
        evidence.TypedValue!.ValueType.Should().Be(EvidenceValueType.Boolean);
    }

    [Fact]
    public async Task AutoLogonCheck_RealSystem_RegistrySource()
    {
        var check = new AutoLogonCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        var evidence = evidenceList.First();
        evidence.SourceType.Should().Be(EvidenceSourceType.Registry);
        evidence.RawOutput.Should().Contain("AutoAdminLogon");
    }
}