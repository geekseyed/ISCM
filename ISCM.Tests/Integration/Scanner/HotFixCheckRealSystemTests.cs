using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using System.Linq;
using System.Runtime.Versioning; // اضافه شد
using System.Threading.Tasks;
using Xunit;

namespace ISCM.Tests.Integration.Scanner;

public class HotFixCheckRealSystemTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task CollectEvidenceAsync_ReturnsFiveTypedEvidences()
    {
        // Arrange
        var check = new HotFixCheck();

        // Act
        var evidences = await check.CollectEvidenceAsync();

        // Assert
        Assert.NotNull(evidences);
        Assert.Equal(5, evidences.Count);

        // Verify HFX-001.1 (Boolean)
        var ev1 = evidences.First(e => e.SubControlId == "HFX-001.1");
        Assert.Equal(CheckStatus.NotScanned, ev1.Evaluation);
        Assert.NotNull(ev1.TypedValue);
        Assert.Equal(EvidenceValueType.Boolean, ev1.TypedValue.ValueType);

        // Verify HFX-001.2 (Duration)
        var ev2 = evidences.First(e => e.SubControlId == "HFX-001.2");
        Assert.Equal(CheckStatus.NotScanned, ev2.Evaluation);
        Assert.NotNull(ev2.TypedValue);
        Assert.Equal(EvidenceValueType.Duration, ev2.TypedValue.ValueType);

        // Verify HFX-001.3 (Integer)
        var ev3 = evidences.First(e => e.SubControlId == "HFX-001.3");
        Assert.Equal(CheckStatus.NotScanned, ev3.Evaluation);
        Assert.NotNull(ev3.TypedValue);
        Assert.Equal(EvidenceValueType.Integer, ev3.TypedValue.ValueType);

        // Verify HFX-001.4 (String)
        var ev4 = evidences.First(e => e.SubControlId == "HFX-001.4");
        Assert.Equal(CheckStatus.NotScanned, ev4.Evaluation);
        Assert.NotNull(ev4.TypedValue);
        Assert.Equal(EvidenceValueType.String, ev4.TypedValue.ValueType);

        // Verify HFX-001.5 (String)
        var ev5 = evidences.First(e => e.SubControlId == "HFX-001.5");
        Assert.Equal(CheckStatus.NotScanned, ev5.Evaluation);
        Assert.NotNull(ev5.TypedValue);
        Assert.Equal(EvidenceValueType.String, ev5.TypedValue.ValueType);
    }
}