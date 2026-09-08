using ISCM.Application.Evaluators;
using ISCM.Application.Evaluators.Typed;
using ISCM.Application.Services;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

/// <summary>
/// Phase 10.8 Batch 3: Real-system integration tests for Secure RDP check.
/// 
/// 1 check migrated:
///   - RdpNlaCheck (RDP-001, 7 SubControls)
/// </summary>
public class SecureRdpCheckRealSystemTests
{
    private static (ExpectedValueParser, TypedEvidenceEvaluator, ControlEvaluator) BuildTypedPipeline()
    {
        var parser = new ExpectedValueParser();
        var typedEvaluator = new TypedEvidenceEvaluator(
            parser,
            new IntegerEvaluator(), new LongEvaluator(), new BooleanEvaluator(),
            new StringEvaluator(), new DurationEvaluator(), new SizeEvaluator(),
            new EnumEvaluator(), new CollectionEvaluator(), new RegistryValueEvaluator(),
            new PolicyValueEvaluator());

        var controlEvaluator = new ControlEvaluator(typedEvaluator);
        return (parser, typedEvaluator, controlEvaluator);
    }

    private static async Task<List<SubControlResult>> EvaluateCheck(
        BaseHardeningCheck check, string checkId, ControlEvaluator controlEvaluator)
    {
        var evidenceList = await check.CollectEvidenceAsync();

        return evidenceList
            .GroupBy(e => e.SubControlId)
            .Select(g =>
            {
                var subControlId = g.Key;
                var controlDefinition = ControlCatalog.GetByCheckId(checkId);
                var subControlDef = controlDefinition?.SubControls
                    .FirstOrDefault(s => s.SubControlId == subControlId);

                var subResult = new SubControlResult
                {
                    SubControlId = subControlId,
                    Status = CheckStatus.NotScanned,
                    EvidenceItems = g.ToList(),
                    EvaluatedAt = DateTime.UtcNow
                };

                if (subControlDef != null && !string.IsNullOrWhiteSpace(subControlDef.ExpectedValue))
                {
                    controlEvaluator.EvaluateSubControlTyped(
                        subResult,
                        subControlDef.ExpectedValue,
                        subControlDef.ExpectedValueType,
                        subControlDef.Operator
                    );
                }

                return subResult;
            })
            .ToList();
    }

    // =========================================================================
    // RdpNlaCheck (RDP-001) - 7 SubControls
    // =========================================================================

    [Fact]
    public async Task RdpNlaCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new RdpNlaCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(7, "RDP-001 has 7 SubControls");

        Console.WriteLine("\n=== RdpNlaCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "RDP-001", controlEvaluator);
        subControlResults.Should().HaveCount(7);

        Console.WriteLine("\n=== RdpNlaCheck - Evaluation ===");
        foreach (var r in subControlResults)
        {
            var ev = r.EvidenceItems.First();
            Console.WriteLine($"  {r.SubControlId}: {r.Status} (Reason={ev.EvaluationReason})");
        }

        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");
            subResult.Status.Should().NotBe(CheckStatus.NotScanned,
                $"SubControl {subResult.SubControlId} should have been evaluated");
        }

        // Summary
        Console.WriteLine("\n=== RdpNlaCheck - Summary ===");
        var passCount = subControlResults.Count(r => r.Status == CheckStatus.Pass);
        var failCount = subControlResults.Count(r => r.Status == CheckStatus.Fail);
        Console.WriteLine($"Pass: {passCount}/7, Fail: {failCount}/7");

        var evaluatedCount = passCount + failCount;
        evaluatedCount.Should().Be(7, "all 7 SubControls should be successfully evaluated");
    }

    [Fact]
    public async Task RdpNlaCheck_CollectEvidenceAsync_ReturnsCorrectSubControlIds()
    {
        var check = new RdpNlaCheck();
        var evidenceList = await check.CollectEvidenceAsync();
        var subControlIds = evidenceList.Select(e => e.SubControlId).ToList();

        subControlIds.Should().HaveCount(7);
        subControlIds.Should().Contain("RDP-001.1", "NLA UserAuthentication");
        subControlIds.Should().Contain("RDP-001.2", "MinEncryptionLevel");
        subControlIds.Should().Contain("RDP-001.3", "fEncryptRPCTraffic");
        subControlIds.Should().Contain("RDP-001.4", "fPromptForPassword");
        subControlIds.Should().Contain("RDP-001.5", "MaxInstanceCount");
        subControlIds.Should().Contain("RDP-001.6", "MaxIdleTime");
        subControlIds.Should().Contain("RDP-001.7", "MaxDisconnectionTime");
    }
}