using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class CryptographyCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsEightTypedEvidences()
    {
        var check = new CryptographyCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(8, evidences.Count);

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
        for (int i = 1; i <= 8; i++)
        {
            var subId = $"CRP-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // Verify specific semantic meaning is preserved in RawOutput
        // "Not Configured" is a valid state (value = -1)
        Assert.All(evidences, e =>
        {
            Assert.False(string.IsNullOrWhiteSpace(e.RawOutput),
                $"RawOutput should not be empty for {e.SubControlId}");
        });
    }
}