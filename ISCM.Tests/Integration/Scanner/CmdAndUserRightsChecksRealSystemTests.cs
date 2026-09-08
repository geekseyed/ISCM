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
/// Phase 10.9: Real-system integration tests for CMD + User Rights checks.
/// 
/// 2 checks migrated:
///   - DisableCmdCheck (CMD-001, 3 SubControls)
///   - UserRightsCheck (URA-001, 9 SubControls)
/// </summary>
public class CmdAndUserRightsChecksRealSystemTests
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
    // DisableCmdCheck (CMD-001) - 3 SubControls
    // =========================================================================

    [Fact]
    public async Task DisableCmdCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new DisableCmdCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(3, "CMD-001 has 3 SubControls");

        Console.WriteLine("\n=== DisableCmdCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "CMD-001", controlEvaluator);
        subControlResults.Should().HaveCount(3);

        Console.WriteLine("\n=== DisableCmdCheck - Evaluation ===");
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
    // UserRightsCheck (URA-001) - 9 SubControls
    // =========================================================================

    [Fact]
    public async Task UserRightsCheck_RealSystem_ProducesValidFindings()
    {
        var (_, _, controlEvaluator) = BuildTypedPipeline();
        var check = new UserRightsCheck();

        var evidenceList = await check.CollectEvidenceAsync();
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(9, "URA-001 has 9 SubControls");

        Console.WriteLine("\n=== UserRightsCheck - Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"  {evidence.SubControlId}: TypedValue={evidence.TypedValue}");
        }

        var subControlResults = await EvaluateCheck(check, "URA-001", controlEvaluator);
        subControlResults.Should().HaveCount(9);

        Console.WriteLine("\n=== UserRightsCheck - Evaluation ===");
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

    [Fact]
    public async Task UserRightsCheck_CollectEvidenceAsync_ReturnsCorrectSubControlIds()
    {
        var check = new UserRightsCheck();
        var evidenceList = await check.CollectEvidenceAsync();
        var subControlIds = evidenceList.Select(e => e.SubControlId).ToList();

        subControlIds.Should().HaveCount(9);
        subControlIds.Should().Contain("URA-001.1", "SeNetworkLogonRight");
        subControlIds.Should().Contain("URA-001.2", "SeDenyNetworkLogonRight");
        subControlIds.Should().Contain("URA-001.3", "SeDenyBatchLogonRight");
        subControlIds.Should().Contain("URA-001.4", "SeDenyServiceLogonRight");
        subControlIds.Should().Contain("URA-001.5", "SeDenyInteractiveLogonRight");
        subControlIds.Should().Contain("URA-001.6", "SeDenyRemoteInteractiveLogonRight");
        subControlIds.Should().Contain("URA-001.7", "SeRemoteInteractiveLogonRight");
        subControlIds.Should().Contain("URA-001.8", "SeDebugPrivilege");
        subControlIds.Should().Contain("URA-001.9", "SeTakeOwnershipPrivilege");
    }
}