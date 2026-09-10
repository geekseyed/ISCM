using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class DeviceGuardCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsSixTypedEvidences()
    {
        var check = new DeviceGuardCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(6, evidences.Count);

        // All must be NotScanned (Phase 11.5 rule)
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // Verify subcontrol presence
        for (int i = 1; i <= 6; i++)
        {
            var subId = $"DVG-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // First 5 are Integer (Registry)
        var regEvidences = evidences.Take(5);
        Assert.All(regEvidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.Integer, e.TypedValue!.ValueType);
            Assert.Equal(EvidenceSourceType.Registry, e.SourceType);
        });

        // Last one is String (CIM)
        var cimEvidence = evidences.Last();
        Assert.Equal("DVG-001.6", cimEvidence.SubControlId);
        Assert.Equal(EvidenceValueType.String, cimEvidence.TypedValue!.ValueType);
        Assert.Equal(EvidenceSourceType.Cim, cimEvidence.SourceType);
    }
}