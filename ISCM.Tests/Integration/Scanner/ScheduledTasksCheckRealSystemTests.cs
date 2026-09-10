using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class ScheduledTasksCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsSixTypedEvidences()
    {
        // Arrange
        var check = new ScheduledTasksCheck();

        // Act
        var evidences = await check.CollectEvidenceAsync();

        // Assert — Total count
        Assert.NotNull(evidences);
        Assert.Equal(6, evidences.Count);

        // Assert — All have NotScanned evaluation (Phase 11.5 rule)
        Assert.All(evidences, e => Assert.Equal(CheckStatus.NotScanned, e.Evaluation));

        // Assert — All have Integer typed value
        Assert.All(evidences, e =>
        {
            Assert.NotNull(e.TypedValue);
            Assert.Equal(EvidenceValueType.Integer, e.TypedValue!.ValueType);
        });

        // Assert — Each subcontrol is present exactly once
        for (int i = 1; i <= 6; i++)
        {
            var subId = $"STK-001.{i}";
            Assert.Contains(evidences, e => e.SubControlId == subId);
        }

        // Assert — All values are non-negative integers
        Assert.All(evidences, e =>
        {
            var raw = e.TypedValue!.RawString;
            Assert.True(int.TryParse(raw, out var v) && v >= 0,
                $"Expected non-negative integer, got '{raw}' for {e.SubControlId}");
        });
    }
}