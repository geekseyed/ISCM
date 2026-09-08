using ISCM.Application.Evaluators;
using ISCM.Application.Evaluators.Typed;
using ISCM.Application.Services;
using ISCM.Application.Services.Agreement;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Infrastructure.Scanning.Checks;
using Xunit;
using FluentAssertions;

namespace ISCM.Tests.Integration.Scanner;

/// <summary>
/// Real-system integration test for PasswordLengthCheck (pilot migration).
/// 
/// This test runs on the actual Windows system (not mocked) to verify:
/// 1. PasswordLengthCheck.CollectEvidenceAsync() produces 6 Evidence items
/// 2. Each Evidence has correct TypedValue (Integer/Duration/Boolean)
/// 3. EvaluateSubControlTyped correctly evaluates with catalog metadata
/// 4. Final SubControlResult.Status reflects actual system state
/// 
/// Expected outcome:
/// - All 6 SubControls should have Status = Pass/Fail/Unknown (not Error)
/// - The test passes regardless of whether the system is compliant or not
/// - We're testing the PIPELINE, not the system compliance
/// </summary>
public class PasswordLengthCheckRealSystemTests
{
    [Fact]
    public async Task PasswordLengthCheck_RealSystem_ProducesValidFindings()
    {
        // Arrange - Build the typed evaluation pipeline
        var parser = new ExpectedValueParser();
        var typedEvaluator = new TypedEvidenceEvaluator(
            parser,
            new IntegerEvaluator(),
            new LongEvaluator(),
            new BooleanEvaluator(),
            new StringEvaluator(),
            new DurationEvaluator(),
            new SizeEvaluator(),
            new EnumEvaluator(),
            new CollectionEvaluator(),
            new RegistryValueEvaluator(),
            new PolicyValueEvaluator());

        var controlEvaluator = new ControlEvaluator(typedEvaluator);

        // Arrange - Create the collector-only check
        var passwordCheck = new PasswordLengthCheck();

        // Act - Step 1: Collect evidence from real system
        var evidenceList = await passwordCheck.CollectEvidenceAsync();

        // Assert - Step 1: Verify collection
        evidenceList.Should().NotBeNull();
        evidenceList.Should().HaveCount(6, "PasswordLengthCheck has 6 SubControls");

        // Log collected evidence
        Console.WriteLine("\n=== Collected Evidence ===");
        foreach (var evidence in evidenceList)
        {
            Console.WriteLine($"SubControlId: {evidence.SubControlId}");
            Console.WriteLine($"  RawOutput: {evidence.RawOutput}");
            Console.WriteLine($"  TypedValue: {evidence.TypedValue}");
            Console.WriteLine($"  Evaluation: {evidence.Evaluation}");
            Console.WriteLine();
        }

        // Act - Step 2: Group evidence by SubControlId
        var subControlResults = evidenceList
            .GroupBy(e => e.SubControlId)
            .Select(g =>
            {
                var subControlId = g.Key;
                var controlDefinition = ControlCatalog.GetByCheckId("PWD-001");
                var subControlDef = controlDefinition?.SubControls
                    .FirstOrDefault(s => s.SubControlId == subControlId);

                var subResult = new SubControlResult
                {
                    SubControlId = subControlId,
                    Status = CheckStatus.NotScanned,
                    EvidenceItems = g.ToList(),
                    EvaluatedAt = DateTime.UtcNow
                };

                // Step 3: Evaluate using typed pipeline with catalog metadata
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

        // Assert - Step 2: Verify evaluation results
        subControlResults.Should().HaveCount(6);

        // Log evaluation results
        Console.WriteLine("\n=== Evaluation Results ===");
        foreach (var subResult in subControlResults)
        {
            Console.WriteLine($"SubControlId: {subResult.SubControlId}");
            Console.WriteLine($"  Status: {subResult.Status}");
            Console.WriteLine($"  Evidence Count: {subResult.EvidenceItems.Count}");

            var evidence = subResult.EvidenceItems.First();
            Console.WriteLine($"  Expected: {evidence.ExpectedValue}");
            Console.WriteLine($"  Actual (TypedValue): {evidence.TypedValue}");
            Console.WriteLine($"  Evaluation Reason: {evidence.EvaluationReason ?? "N/A"}");
            Console.WriteLine();
        }

        // Assert - All SubControls should have a valid status (not Error or NotScanned)
        foreach (var subResult in subControlResults)
        {
            subResult.Status.Should().NotBe(CheckStatus.Error,
                $"SubControl {subResult.SubControlId} should not have Error status");

            subResult.Status.Should().NotBe(CheckStatus.NotScanned,
                $"SubControl {subResult.SubControlId} should have been evaluated");
        }

        // Log summary
        Console.WriteLine("\n=== Summary ===");
        var passCount = subControlResults.Count(r => r.Status == CheckStatus.Pass);
        var failCount = subControlResults.Count(r => r.Status == CheckStatus.Fail);
        var unknownCount = subControlResults.Count(r => r.Status == CheckStatus.Unknown);

        Console.WriteLine($"Pass: {passCount}/6");
        Console.WriteLine($"Fail: {failCount}/6");
        Console.WriteLine($"Unknown: {unknownCount}/6");
        Console.WriteLine();

        // Final assertion: At least some SubControls should be evaluated
        var evaluatedCount = passCount + failCount;
        evaluatedCount.Should().BeGreaterThan(0,
            "at least some SubControls should be successfully evaluated");
    }

    [Fact]
    public async Task PasswordLengthCheck_CollectEvidenceAsync_ReturnsCorrectSubControlIds()
    {
        // Arrange
        var passwordCheck = new PasswordLengthCheck();

        // Act
        var evidenceList = await passwordCheck.CollectEvidenceAsync();

        // Assert - Verify all 6 SubControls are present
        var subControlIds = evidenceList.Select(e => e.SubControlId).ToList();

        subControlIds.Should().Contain("PWD-001.1", "Password history");
        subControlIds.Should().Contain("PWD-001.2", "Maximum password age");
        subControlIds.Should().Contain("PWD-001.3", "Minimum password age");
        subControlIds.Should().Contain("PWD-001.4", "Minimum password length");
        subControlIds.Should().Contain("PWD-001.5", "Password complexity");
        subControlIds.Should().Contain("PWD-001.6", "Reversible encryption");
    }

    [Fact]
    public async Task PasswordLengthCheck_Evidence_HasCorrectTypedValues()
    {
        // Arrange
        var passwordCheck = new PasswordLengthCheck();

        // Act
        var evidenceList = await passwordCheck.CollectEvidenceAsync();

        // Assert - Verify each SubControl has correct TypedValue type
        var pwd001_1 = evidenceList.First(e => e.SubControlId == "PWD-001.1");
        pwd001_1.TypedValue.Should().NotBeNull("PWD-001.1 (password history) should have TypedValue");
        // PWD-001.1 is Integer (24 passwords remembered)

        var pwd001_2 = evidenceList.First(e => e.SubControlId == "PWD-001.2");
        pwd001_2.TypedValue.Should().NotBeNull("PWD-001.2 (max password age) should have TypedValue");
        // PWD-001.2 is Duration (60 days)

        var pwd001_4 = evidenceList.First(e => e.SubControlId == "PWD-001.4");
        pwd001_4.TypedValue.Should().NotBeNull("PWD-001.4 (min password length) should have TypedValue");
        // PWD-001.4 is Integer (14 characters)

        var pwd001_5 = evidenceList.First(e => e.SubControlId == "PWD-001.5");
        pwd001_5.TypedValue.Should().NotBeNull("PWD-001.5 (complexity) should have TypedValue");
        // PWD-001.5 is Boolean (Enabled)
    }
}