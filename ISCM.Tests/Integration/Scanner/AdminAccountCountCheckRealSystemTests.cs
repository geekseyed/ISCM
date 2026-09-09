using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

public class AdminAccountCountCheckRealSystemTests
{
    [Fact]
    public async Task AdminAccountCountCheck_RealSystem_ProducesValidFindings()
    {
        var check = new AdminAccountCountCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        evidenceList.Should().NotBeNull();
        evidenceList.Should().NotBeEmpty();

        var evidence = evidenceList.First();
        evidence.SubControlId.Should().Be("ADM-001.1");
        evidence.Evaluation.Should().Be(CheckStatus.NotScanned);
        evidence.TypedValue.Should().NotBeNull();
        evidence.RawOutput.Should().NotBeNullOrWhiteSpace();
        evidence.TypedValue!.ValueType.Should().Be(EvidenceValueType.Integer);
    }

    [Fact]
    public async Task AdminAccountCountCheck_RealSystem_MultiSourceVerification()
    {
        var check = new AdminAccountCountCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        evidenceList.Should().HaveCountGreaterThanOrEqualTo(1);
        var evidence = evidenceList.First();
        evidence.SourceType.Should().BeOneOf(
            EvidenceSourceType.PowerShell,
            EvidenceSourceType.Other,
            EvidenceSourceType.Wmi
        );
    }
}