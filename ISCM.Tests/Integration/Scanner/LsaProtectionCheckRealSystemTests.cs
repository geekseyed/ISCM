using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class LsaProtectionCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsSixTypedEvidences()
    {
        var check = new LsaProtectionCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(6, evidences.Count);

        // All must be NotScanned (Phase 11.5 rule)
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // All must be Integer type
        Assert.All(evidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.Integer, e.TypedValue!.ValueType);
        });

        // All must be Registry source
        Assert.All(evidences, e => Assert.Equal(EvidenceSourceType.Registry, e.SourceType));

        // Each subcontrol must be present exactly once
        for (int i = 1; i <= 6; i++)
        {
            var subId = $"LSA-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }
    }
}