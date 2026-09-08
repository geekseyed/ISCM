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
/// Phase 10.8 Batch 1: Real-system integration tests for Registry-only checks.
/// 
/// 4 checks migrated:
///   - AutoRunDisabledCheck (ARD-001, 3 SubControls)
///   - UserAccountControlCheck (UAC-001, 3 SubControls)
///   - LmCompatibilityCheck (LM-001, 2 SubControls)
///   - CredentialGuardCheck (CRG-001, 6 SubControls)
/// </summary>
public class RegistryChecksBatch1RealSystemTests
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
    // AutoRunDisabledCheck (ARD-001) - 3 SubControls
    // =========================================================================

    [Fact]
    public async Task AutoRunDisabledCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new AutoRunDisabledCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(3, "ARD-001 has 3 SubControls");

        Console.WriteLine("\n=== AutoRunDisabledCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "ARD-001", controlEvaluator);
        subControlResults.Should().HaveCount(3);

        Console.WriteLine("\n=== AutoRunDisabledCheck - Evaluation ===");
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
    // UserAccountControlCheck (UAC-001) - 3 SubControls
    // =========================================================================

    [Fact]
    public async Task UserAccountControlCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new UserAccountControlCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(3, "UAC-001 has 3 SubControls");

        Console.WriteLine("\n=== UserAccountControlCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "UAC-001", controlEvaluator);
        subControlResults.Should().HaveCount(3);

        Console.WriteLine("\n=== UserAccountControlCheck - Evaluation ===");
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
    // LmCompatibilityCheck (LM-001) - 2 SubControls
    // =========================================================================

    [Fact]
    public async Task LmCompatibilityCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new LmCompatibilityCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(2, "LM-001 has 2 SubControls");

        Console.WriteLine("\n=== LmCompatibilityCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "LM-001", controlEvaluator);
        subControlResults.Should().HaveCount(2);

        Console.WriteLine("\n=== LmCompatibilityCheck - Evaluation ===");
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
    // CredentialGuardCheck (CRG-001) - 6 SubControls
    // =========================================================================

    [Fact]
    public async Task CredentialGuardCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new CredentialGuardCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(6, "CRG-001 has 6 SubControls");

        Console.WriteLine("\n=== CredentialGuardCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "CRG-001", controlEvaluator);
        subControlResults.Should().HaveCount(6);

        Console.WriteLine("\n=== CredentialGuardCheck - Evaluation ===");
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