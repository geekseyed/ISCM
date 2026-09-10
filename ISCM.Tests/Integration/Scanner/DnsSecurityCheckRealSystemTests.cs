using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class DnsSecurityCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsSixTypedEvidences()
    {
        var check = new DnsSecurityCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(6, evidences.Count);

        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // Verify each subcontrol exists
        for (int i = 1; i <= 6; i++)
        {
            var subId = $"DNS-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // Integer types: 1.1, 1.2, 1.4, 1.6
        Assert.Equal(EvidenceValueType.Integer,
            evidences.First(e => e.SubControlId == "DNS-001.1").TypedValue!.ValueType);
        Assert.Equal(EvidenceValueType.Integer,
            evidences.First(e => e.SubControlId == "DNS-001.2").TypedValue!.ValueType);
        Assert.Equal(EvidenceValueType.Integer,
            evidences.First(e => e.SubControlId == "DNS-001.4").TypedValue!.ValueType);
        Assert.Equal(EvidenceValueType.Integer,
            evidences.First(e => e.SubControlId == "DNS-001.6").TypedValue!.ValueType);

        // String types: 1.3 (mDNS), 1.5 (Dnscache)
        Assert.Equal(EvidenceValueType.String,
            evidences.First(e => e.SubControlId == "DNS-001.3").TypedValue!.ValueType);
        Assert.Equal(EvidenceValueType.String,
            evidences.First(e => e.SubControlId == "DNS-001.5").TypedValue!.ValueType);
    }
}