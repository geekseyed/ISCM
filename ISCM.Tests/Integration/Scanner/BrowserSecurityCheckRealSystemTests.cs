using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class BrowserSecurityCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsEightTypedEvidences()
    {
        var check = new BrowserSecurityCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(8, evidences.Count);

        // All must be NotScanned (Phase 11.5 rule)
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // All must have Integer typed value
        Assert.All(evidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.Integer, e.TypedValue!.ValueType);
        });

        // Each subcontrol must be present exactly once
        for (int i = 1; i <= 8; i++)
        {
            var subId = $"BRW-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // All must have Registry source type
        Assert.All(evidences, e => Assert.Equal(EvidenceSourceType.Registry, e.SourceType));
    }
}