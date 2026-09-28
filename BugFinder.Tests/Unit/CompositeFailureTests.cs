using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;

namespace ISCM.Tests.Unit.BugFinder;

public class CompositeFailureTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    private static FailureInstance Instance(
        string testName, string raw, string sessionSeed, DateTimeOffset? at = null)
    {
        var material = new FailureSignatureMaterial
        {
            TestIdentity = new FailureIdentity
            {
                AssemblyName = "ASM",
                ClassName = "NS.MyClass",
                TestName = testName
            },
            RawMessage = raw
        };
        var derivation = new FailureSignatureService().Generate(material);
        var session = ExecutionSessionId.Create($"ES-{sessionSeed}{Hex32()[1..]}");

        return FailureInstanceFactory.Create(
            material, derivation, session, at ?? T0);
    }

    private static string Hex32() => "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";

    // Stage 2.5.5 — THE KBF-02-007 scenario: a two-failure composite test
    // produces TWO component instances (the old one-result shape is gone)
    [Fact]
    public void TwoFailureComposite_ProducesTwoComponentInstances()
    {
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c2 = Instance("MyTest", "assertion B failed", "a");

        var build = CompositeFailureBuilder.Build(
            aggregate: null, components: new[] { c1, c2 },
            evidenceNote: "test reported two assertion failures");

        build.Components.Should().HaveCount(2);
        build.Components.Select(x => x.FailureId).Distinct().Should().HaveCount(2);
        build.Link!.LinkKind.Should().Be(CompositeLinkKind.ComponentsOnly);
    }

    // 2.5.1 — each component is an independent instance with its own signature
    [Fact]
    public void Components_IndependentInstances_DistinctSignatures()
    {
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c2 = Instance("MyTest", "assertion B failed", "a");

        c1.Signature.Should().NotBe(c2.Signature);
        c1.InstanceId.Should().NotBe(c2.InstanceId);
    }

    // 2.5.2 — the aggregate is its own failure (wrapper content signature)
    [Fact]
    public void Aggregate_HasOwnSignature_DifferentFromComponents()
    {
        var aggregate = Instance("MyTest", "composite: 2 failures in fixture teardown", "a");
        var c1 = Instance("MyTest", "assertion A failed", "a");

        aggregate.Signature.Should().NotBe(c1.Signature);
    }

    // 2.5.3 — full link: aggregate + two components
    [Fact]
    public void Build_FullLink_AggregateAndComponents()
    {
        var aggregate = Instance("MyTest", "composite: 2 failures in fixture teardown", "a");
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c2 = Instance("MyTest", "assertion B failed", "a");

        var build = CompositeFailureBuilder.Build(
            aggregate, new[] { c1, c2 }, "fixture teardown collected both");

        build.Link!.LinkKind.Should().Be(CompositeLinkKind.AggregateWithComponents);
        build.Link.AggregateFailureId.Should().Be(aggregate.FailureId);
        build.Link.AggregateInstanceId.Value
            .Should().StartWith("FI|").And.Contain(aggregate.Session.Value);
        build.Link.ComponentFailureIds.Should().HaveCount(2);
        build.Link.ComponentInstanceIds.Should().HaveCount(2);
        build.Link.EvidenceNote.Should().Contain("fixture teardown");
    }

    // 2.5.3 — component ids de-duplicated and ordered
    [Fact]
    public void Build_ComponentIds_DeduplicatedAndOrdered()
    {
        var aggregate = Instance("MyTest", "composite wrapper", "a");
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c2 = Instance("MyTest", "assertion B failed", "a");

        var build = CompositeFailureBuilder.Build(
            aggregate, new[] { c1, c2, c1 }, "note");   // duplicate instance

        build.Link!.ComponentFailureIds
            .Select(f => f.Value).Should().BeInAscendingOrder();
        build.Link.ComponentInstanceIds
            .Select(i => i.Value).Should().BeInAscendingOrder();
    }

    // 2.5.3 — the same component may fan out to several composites
    [Fact]
    public void Build_ComponentFanOut_Allowed()
    {
        var shared = Instance("MyTest", "assertion A failed", "a");
        var agg1 = Instance("MyTest", "composite teardown run 1", "a");
        var agg2 = Instance("MyTest", "composite teardown run 2", "a");

        var b1 = CompositeFailureBuilder.Build(agg1, new[] { shared }, "run 1");
        var b2 = CompositeFailureBuilder.Build(agg2, new[] { shared }, "run 2");

        b1.Link!.ComponentFailureIds[0].Should().Be(b2.Link!.ComponentFailureIds[0]);
        b1.Link.AggregateFailureId.Should().NotBe(b2.Link.AggregateFailureId);
    }

    // 2.5.4 — component loss prevention: dedup keeps aggregate AND
    // components as separate canonical groups (nothing swallowed)
    [Fact]
    public void Deduplication_KeepsAggregateAndComponents_SeparateGroups()
    {
        var aggregate = Instance("MyTest", "composite: 2 failures in fixture teardown", "a");
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c2 = Instance("MyTest", "assertion B failed", "a");

        var dedup = new FailureDeduplicationService()
            .Deduplicate(new[] { aggregate, c1, c2 });

        dedup.CanonicalCount.Should().Be(3);            // 1 aggregate + 2 components
        dedup.CanonicalFailures.Should().OnlyContain(c => c.OccurrenceCount == 1);
        dedup.CanonicalFailures
            .Count(c => c.FailureId.Value == aggregate.FailureId.Value)
            .Should().Be(1);                             // aggregate survived intact
    }

    // 2.5.4 — H-02.4 duplicate-prevention interacts correctly: a second
    // occurrence of the SAME component is a dedup matter, not composite loss
    [Fact]
    public void DuplicateComponent_GoesToItsOwnCanonicalGroup()
    {
        var aggregate = Instance("MyTest", "composite wrapper", "a");
        var c1 = Instance("MyTest", "assertion A failed", "a");
        var c1again = Instance("MyTest", "assertion A failed", "a");   // same signature, same session

        var dedup = new FailureDeduplicationService()
            .Deduplicate(new[] { aggregate, c1, c1again });

        dedup.CanonicalCount.Should().Be(2);            // aggregate + one component group
        dedup.CanonicalFailures
            .First(c => c.FailureId.Value == c1.FailureId.Value)
            .OccurrenceCount.Should().Be(2);             // duplicates grouped, not lost
    }

    // Validation — component with the aggregate's signature is a duplicate, not a part
    [Fact]
    public void Build_ComponentWithAggregateSignature_Throws()
    {
        var aggregate = Instance("MyTest", "same content", "a");
        var clone = Instance("MyTest", "same content", "a");

        Action act = () => CompositeFailureBuilder.Build(
            aggregate, new[] { clone }, "note");

        act.Should().Throw<ArgumentException>()
            .WithMessage("*duplicate*");
    }

    // Validation — empty evidence note refused (links are evidence)
    [Fact]
    public void Build_EmptyEvidenceNote_Throws()
    {
        var aggregate = Instance("MyTest", "wrapper", "a");
        var c = Instance("MyTest", "component", "a");

        Action blank = () => CompositeFailureBuilder.Build(aggregate, new[] { c }, "  ");
        blank.Should().Throw<ArgumentException>();
    }

    // Validation — nothing at all refused
    [Fact]
    public void Build_NothingProvided_Throws()
    {
        Action act = () => CompositeFailureBuilder.Build(null, null, "note");
        act.Should().Throw<ArgumentException>();
    }

    // Validation — null component in the list refused
    [Fact]
    public void Build_NullComponent_Throws()
    {
        var aggregate = Instance("MyTest", "wrapper", "a");
        Action act = () => CompositeFailureBuilder.Build(
                    aggregate, new FailureInstance[] { Instance("MyTest", "c", "a"), null! }, "note");
        act.Should().Throw<ArgumentException>();
    }

    // Aggregate-only and components-only modes
    [Fact]
    public void Build_AggregateOnly_And_ComponentsOnly()
    {
        var aggregate = Instance("MyTest", "wrapper only", "a");
        var c = Instance("MyTest", "loose component", "a");

        var aggOnly = CompositeFailureBuilder.Build(aggregate, null, "wrapper seen alone");
        var compOnly = CompositeFailureBuilder.Build(null, new[] { c }, "components seen without wrapper");

        aggOnly.Link!.LinkKind.Should().Be(CompositeLinkKind.AggregateOnly);
        compOnly.Link!.LinkKind.Should().Be(CompositeLinkKind.ComponentsOnly);
        aggOnly.Link.AggregateFailureId.Should().Be(aggregate.FailureId);
        compOnly.Link.ComponentFailureIds.Should().ContainSingle();
    }
}