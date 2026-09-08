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
/// Phase 10.8 Batch 2: Real-system integration tests for Network + PowerShell checks.
/// 
/// 4 checks migrated:
///   - FirewallDomainProfileCheck (FW-001, 4 SubControls)
///   - LlmnrNetbiosCheck (LLN-001, 7 SubControls)
///   - SmbV1ProtocolCheck (SMB-001, 5 SubControls)
///   - WindowsUpdateCheck (WUP-001, 4 SubControls)
/// </summary>
public class NetworkChecksBatch2RealSystemTests
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
    // FirewallDomainProfileCheck (FW-001) - 4 SubControls
    // =========================================================================

    [Fact]
    public async Task FirewallDomainProfileCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new FirewallDomainProfileCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(4, "FW-001 has 4 SubControls migrated");

        Console.WriteLine("\n=== FirewallDomainProfileCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "FW-001", controlEvaluator);
        subControlResults.Should().HaveCount(4);

        Console.WriteLine("\n=== FirewallDomainProfileCheck - Evaluation ===");
        foreach (var r in subControlResults)
        {
            var ev = r.EvidenceItems.First();
            Console.WriteLine($"  {r.SubControlId}: {r.Status} (Reason={ev.EvaluationReason})");
        }

        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");
        }
    }

    // =========================================================================
    // LlmnrNetbiosCheck (LLN-001) - 7 SubControls
    // =========================================================================

    [Fact]
    public async Task LlmnrNetbiosCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new LlmnrNetbiosCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(7, "LLN-001 has 7 SubControls migrated");

        Console.WriteLine("\n=== LlmnrNetbiosCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "LLN-001", controlEvaluator);
        subControlResults.Should().HaveCount(7);

        Console.WriteLine("\n=== LlmnrNetbiosCheck - Evaluation ===");
        foreach (var r in subControlResults)
        {
            var ev = r.EvidenceItems.First();
            Console.WriteLine($"  {r.SubControlId}: {r.Status} (Reason={ev.EvaluationReason})");
        }

        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");
        }
    }

    // =========================================================================
    // SmbV1ProtocolCheck (SMB-001) - 5 SubControls
    // =========================================================================

    [Fact]
    public async Task SmbV1ProtocolCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new SmbV1ProtocolCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(5, "SMB-001 has 5 SubControls migrated");

        Console.WriteLine("\n=== SmbV1ProtocolCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "SMB-001", controlEvaluator);
        subControlResults.Should().HaveCount(5);

        Console.WriteLine("\n=== SmbV1ProtocolCheck - Evaluation ===");
        foreach (var r in subControlResults)
        {
            var ev = r.EvidenceItems.First();
            Console.WriteLine($"  {r.SubControlId}: {r.Status} (Reason={ev.EvaluationReason})");
        }

        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");
        }
    }

    // =========================================================================
    // WindowsUpdateCheck (WUP-001) - 4 SubControls
    // =========================================================================

    [Fact]
    public async Task WindowsUpdateCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new WindowsUpdateCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(4, "WUP-001 has 4 SubControls migrated");

        Console.WriteLine("\n=== WindowsUpdateCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "WUP-001", controlEvaluator);
        subControlResults.Should().HaveCount(4);

        Console.WriteLine("\n=== WindowsUpdateCheck - Evaluation ===");
        foreach (var r in subControlResults)
        {
            var ev = r.EvidenceItems.First();
            Console.WriteLine($"  {r.SubControlId}: {r.Status} (Reason={ev.EvaluationReason})");
        }

        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");
        }
    }
}