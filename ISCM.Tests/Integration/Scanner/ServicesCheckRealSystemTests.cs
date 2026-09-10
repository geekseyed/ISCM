using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class ServicesCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_Returns13TypedEvidences()
    {
        // Arrange
        var check = new ServicesCheck();

        // Act
        var evidences = await check.CollectEvidenceAsync();

        // Assert — Total count
        Assert.NotNull(evidences);
        Assert.Equal(13, evidences.Count);

        // Assert — All have NotScanned evaluation (Phase 11.5 rule)
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // Assert — All have String typed value
        Assert.All(evidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.String, e.TypedValue!.ValueType);
        });

        // Assert — Each subcontrol is present exactly once
        for (int i = 1; i <= 13; i++)
        {
            var subId = $"SVC-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // Assert — TypedValue is "Running", "Stopped", or "Unknown" (no raw text leakage)
        Assert.All(evidences, e =>
        {
            var value = e.TypedValue!.RawString;
            Assert.True(value == "Running" || value == "Stopped" || value == "Unknown",
                $"Unexpected status value '{value}' for {e.SubControlId}");
        });
    }
}