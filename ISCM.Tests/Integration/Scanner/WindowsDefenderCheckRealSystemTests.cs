using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

public class WindowsDefenderCheckRealSystemTests
{
    [Fact]
    public async Task WindowsDefenderCheck_RealSystem_ProducesValidFindings()
    {
        var check = new WindowsDefenderCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(3);

        var def0011 = evidenceList.FirstOrDefault(e => e.SubControlId == "DEF-001.1");
        def0011.Should().NotBeNull();
        def0011!.Evaluation.Should().Be(CheckStatus.NotScanned);
        def0011.TypedValue.Should().NotBeNull();
        def0011.TypedValue!.ValueType.Should().Be(EvidenceValueType.Boolean);

        var def0012 = evidenceList.FirstOrDefault(e => e.SubControlId == "DEF-001.2");
        def0012.Should().NotBeNull();
        def0012!.Evaluation.Should().Be(CheckStatus.NotScanned);
        def0012.TypedValue.Should().NotBeNull();
        def0012.TypedValue!.ValueType.Should().Be(EvidenceValueType.Boolean);

        var def0013 = evidenceList.FirstOrDefault(e => e.SubControlId == "DEF-001.3");
        def0013.Should().NotBeNull();
        def0013!.Evaluation.Should().Be(CheckStatus.NotScanned);
        def0013.TypedValue.Should().NotBeNull();
        def0013.TypedValue!.ValueType.Should().Be(EvidenceValueType.Boolean);
    }

    [Fact]
    public async Task WindowsDefenderCheck_RealSystem_RegistryAndPowerShellSources()
    {
        var check = new WindowsDefenderCheck();
        var evidenceList = await check.CollectEvidenceAsync();

        var registryEvidence = evidenceList.Where(e => e.SourceType == EvidenceSourceType.Registry).ToList();
        var powershellEvidence = evidenceList.Where(e => e.SourceType == EvidenceSourceType.PowerShell).ToList();

        (registryEvidence.Count + powershellEvidence.Count).Should().BeGreaterThan(0);
    }
}