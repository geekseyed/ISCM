using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;

namespace ISCM.Tests.Unit.BugFinder;

/// <summary>
/// H-02.7: Failure Identity Verification — the closing scenario family
/// of H-02. Each stage runs the FULL pipeline end-to-end
/// (material 2.1 -> signature 2.2 -> instance 2.3 -> dedup 2.4),
/// proving the H-02 exit gate:
///   "Two materially different failures in the same test must never
///    collapse into one canonical failure identity."
/// Zero production code — this family only orchestrates.
/// </summary>
public class FailureIdentityVerificationTests
{
    private readonly FailureSignatureService _signatures = new();
    private readonly FailureDeduplicationService _dedup = new();

    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    private static FailureInstance Instance(
        string sessionSeed,
        string testName = "NS.MyClass.MyTest",
        string? raw = "boom",
        string? assertionType = null,
        string? exceptionType = null,
        string? filePath = null,
        int? line = null,
        DateTimeOffset? at = null)
    {
        var material = new FailureSignatureMaterial
        {
            TestIdentity = FailureIdentityProjection.FromInput(
                new FailureIdentityInput { TestIdentity = testName }),
            AssertionType = assertionType,
            ExceptionTypeName = exceptionType,
            Location = filePath is null ? null : new SourceLocation
            {
                FilePath = filePath,
                LineNumber = line,
                MethodName = "Evaluate"
            },
            RawMessage = raw
        };
        var derivation = _signaturesLocal.Generate(material);
        var session = ExecutionSessionId.Create($"ES-{sessionSeed}{Hex32()[1..]}");
        return FailureInstanceFactory.Create(material, derivation, session, at ?? T0);
    }

    private static readonly FailureSignatureService _signaturesLocal = new();

    private static string Hex32() => "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";

    private FailureDeduplicationReport Dedup(params FailureInstance[] instances) =>
        _dedup.Deduplicate(instances);

    // ================================================================
    // Stage 2.7.1 — same test / same failure → ONE canonical
    // ================================================================

    [Fact]
    public void Verify_2_7_1_SameTestSameFailure_MergesToOneCanonical()
    {
        var first = Instance("a", raw: "expected 512, actual 1024");
        var second = Instance("b", raw: "expected 512, actual 1024", at: T0.AddHours(1));

        var report = Dedup(first, second);

        report.CanonicalCount.Should().Be(1);
        var group = report.CanonicalFailures[0];
        group.OccurrenceCount.Should().Be(2);
        group.IsRecurring.Should().BeTrue();
        group.Instances.Select(i => i.TestDefinitionId).Distinct().Should().ContainSingle();
    }

    // ================================================================
    // Stage 2.7.2 — same test / different assertion → TWO canonicals
    // ================================================================

    [Fact]
    public void Verify_2_7_2_SameTestDifferentAssertion_TwoCanonicals()
    {
        var equality = Instance("a", raw: "assert", assertionType: "Equality");
        var collection = Instance("b", raw: "assert", assertionType: "Collection");

        var report = Dedup(equality, collection);

        report.CanonicalCount.Should().Be(2);
        report.CanonicalFailures.Should().OnlyContain(c => c.OccurrenceCount == 1);
        report.CanonicalFailures.Select(c => c.FailureId.Value)
            .Distinct().Should().HaveCount(2);
    }

    // Same test, different assertion MESSAGE (meaningful magnitude) also splits
    [Fact]
    public void Verify_2_7_2_SameTestDifferentAssertionMessage_TwoCanonicals()
    {
        var a = Instance("a", raw: "expected 512, actual 1024");
        var b = Instance("a", raw: "expected 512, actual 512");

        var report = Dedup(a, b);

        report.CanonicalCount.Should().Be(2);   // magnitude difference preserved (2.2.6)
    }

    // ================================================================
    // Stage 2.7.3 — same test / different exception → TWO canonicals
    // ================================================================

    [Fact]
    public void Verify_2_7_3_SameTestDifferentExceptionType_TwoCanonicals()
    {
        var invalidOp = Instance("a", exceptionType: "System.InvalidOperationException", raw: "wrapped");
        var timeout = Instance("a", exceptionType: "System.TimeoutException", raw: "wrapped");

        var report = Dedup(invalidOp, timeout);

        report.CanonicalCount.Should().Be(2);
    }

    // Inner-chain difference also separates
    [Fact]
    public void Verify_2_7_3_SameTestDifferentInnerChain_TwoCanonicals()
    {
        var withInner = new FailureSignatureMaterial
        {
            TestIdentity = FailureIdentityProjection.FromInput(
                new FailureIdentityInput { TestIdentity = "NS.MyClass.MyTest" }),
            ExceptionTypeName = "System.InvalidOperationException",
            InnerExceptionTypeNames = new[] { "System.IO.IOException" },
            RawMessage = "wrapped"
        };
        var withoutInner = new FailureSignatureMaterial
        {
            TestIdentity = FailureIdentityProjection.FromInput(
                new FailureIdentityInput { TestIdentity = "NS.MyClass.MyTest" }),
            ExceptionTypeName = "System.InvalidOperationException",
            RawMessage = "wrapped"
        };

        var report = Dedup(
            BuildInstance(withInner, "a"),
            BuildInstance(withoutInner, "a"));

        report.CanonicalCount.Should().Be(2);
    }

    // ================================================================
    // Stage 2.7.4 — same test / different source location → TWO canonicals
    // ================================================================

    [Fact]
    public void Verify_2_7_4_SameTestDifferentLocationLines_TwoCanonicals()
    {
        var at42 = Instance("a", raw: "guard failed", filePath: "Calc.cs", line: 42);
        var at99 = Instance("a", raw: "guard failed", filePath: "Calc.cs", line: 99);

        var report = Dedup(at42, at99);

        // Location is part of the canonical form (2.2.4) — different lines
        // are materially different failure records even with equal messages.
        report.CanonicalCount.Should().Be(2);
    }

    [Fact]
    public void Verify_2_7_4_SameTestDifferentFiles_TwoCanonicals()
    {
        var inCalc = Instance("a", raw: "guard failed", filePath: "Calc.cs", line: 42);
        var inHelper = Instance("a", raw: "guard failed", filePath: "Helper.cs", line: 42);

        var report = Dedup(inCalc, inHelper);

        report.CanonicalCount.Should().Be(2);
    }

    // Complementary honesty: identical location AND message AND test =
    // same failure, regardless of which session recorded it
    [Fact]
    public void Verify_2_7_4_SameLocationSameMessage_SameCanonical()
    {
        var fromTrx = Instance("a", raw: "guard failed", filePath: "Calc.cs", line: 42);
        var fromConsole = Instance("b", raw: "guard failed", filePath: "Calc.cs", line: 42);

        var report = Dedup(fromTrx, fromConsole);

        report.CanonicalCount.Should().Be(1);
        report.CanonicalFailures[0].DistinctSessionCount.Should().Be(2);
    }

    // ================================================================
    // Stage 2.7.5 — composite failure case
    // ================================================================

    [Fact]
    public void Verify_2_7_5_Composite_AggregateAndComponents_AllSeparate()
    {
        var aggregate = Instance("a", raw: "composite: 2 failures in fixture teardown");
        var c1 = Instance("a", raw: "assertion A failed");
        var c2 = Instance("a", raw: "assertion B failed");

        var report = Dedup(aggregate, c1, c2);

        report.CanonicalCount.Should().Be(3);   // nothing swallowed (2.5.4)
        report.CanonicalFailures.Should().OnlyContain(c => c.OccurrenceCount == 1);
    }

    // And the composite link references the canonical groups
    [Fact]
    public void Verify_2_7_5_CompositeLink_ReferencesCanonicalIds()
    {
        var aggregate = Instance("a", raw: "composite: 2 failures in fixture teardown");
        var c1 = Instance("a", raw: "assertion A failed");
        var c2 = Instance("a", raw: "assertion B failed");

        var dedup = Dedup(aggregate, c1, c2);
        var link = CompositeFailureBuilder.Build(
            aggregate, new[] { c1, c2 }, "fixture teardown collected both");

        var canonicalIds = dedup.CanonicalFailures.Select(c => c.FailureId.Value).ToList();
        // بعد (H-02.5: ids live on the Link record, not the Build):
        canonicalIds.Should().Contain(link.Link!.AggregateFailureId.Value);
        link.Link.ComponentFailureIds.Should().OnlyContain(id => canonicalIds.Contains(id.Value));
    }

    // ================================================================
    // Stage 2.7.6 — cross-session recurrence
    // ================================================================

    [Fact]
    public void Verify_2_7_6_CrossSessionRecurrence_LinkedBySignature()
    {
        var run1 = Instance("a", raw: "expected 512, actual 1024", at: T0);
        var run2 = Instance("b", raw: "expected 512, actual 1024", at: T0.AddHours(2));
        var run3 = Instance("c", raw: "expected 512, actual 1024", at: T0.AddHours(6));

        var report = Dedup(run1, run2, run3);

        report.CanonicalCount.Should().Be(1);
        var group = report.CanonicalFailures[0];

        group.OccurrenceCount.Should().Be(3);
        group.DistinctSessionCount.Should().Be(3);
        group.IsCrossSessionRecurring.Should().BeTrue();
        group.FirstSeenUtc.Should().Be(T0);
        group.LastSeenUtc.Should().Be(T0.AddHours(6));
    }

    // ================================================================
    // Exit-gate composition — all six scenarios in one dedup universe
    // ================================================================

    [Fact]
    public void Verify_ExitGate_AllScenarioKinds_CoexistWithoutCrossCollapse()
    {
        // 2.7.1 pair (recurring) + 2.7.2 distinct + 2.7.3 distinct +
        // 2.7.5 composite + components — all in one universe
        var recurring1 = Instance("a", raw: "expected 512, actual 1024", at: T0);
        var recurring2 = Instance("b", raw: "expected 512, actual 1024", at: T0.AddHours(1));
        var equality = Instance("a", raw: "assert", assertionType: "Equality");
        var timeout = Instance("a", exceptionType: "System.TimeoutException", raw: "wrapped");
        var aggregate = Instance("a", raw: "composite: fixture teardown");
        var component = Instance("a", raw: "assertion A failed");

        var report = Dedup(recurring1, recurring2, equality, timeout, aggregate, component);

        // 6 inputs -> 5 canonical groups:
        //   recurring pair (1) + equality (1) + timeout (1)
        //   + aggregate (1) + component (1)
        report.InputInstanceCount.Should().Be(6);
        report.CanonicalCount.Should().Be(5);
        report.CollapsedInstanceCount.Should().Be(1);
        report.RecurringCount.Should().Be(1);

        // the only recurring group is exactly the recurring pair
        report.CanonicalFailures
            .Single(c => c.IsRecurring).OccurrenceCount.Should().Be(2);
        report.CrossSessionRecurringCount.Should().Be(1);
    }

    // H-01.4 guard — zero-knowledge material cannot enter the pipeline
    [Fact]
    public void Verify_ZeroKnowledge_Material_RefusedBeforePipeline()
    {
        Action act = () => _signaturesLocal.Generate(new FailureSignatureMaterial());
        act.Should().Throw<ArgumentException>().WithMessage("*zero knowledge*");
    }

    // Helper — build an instance from a custom material
    private static FailureInstance BuildInstance(FailureSignatureMaterial material, string sessionSeed)
    {
        var derivation = new FailureSignatureService().Generate(material);
        var session = ExecutionSessionId.Create($"ES-{sessionSeed}{Hex32()[1..]}");
        return FailureInstanceFactory.Create(material, derivation, session, T0);
    }
}