using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class KernelMitigationsCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsSixTypedEvidences()
    {
        var check = new KernelMitigationsCheck();
        var evidences = await check.CollectEvidenceAsync();

        Assert.NotNull(evidences);
        Assert.Equal(6, evidences.Count);

        // All must be NotScanned
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // All must be Boolean type
        Assert.All(evidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.Boolean, e.TypedValue!.ValueType);
        });

        // All KRN-001.1 to KRN-001.6 must be present
        for (int i = 1; i <= 6; i++)
        {
            Assert.Contains(evidences, e => e.SubControlId == $"KRN-001.{i}");
        }
    }
}