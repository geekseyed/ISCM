using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;

namespace ISCM.Tests.Unit.BugFinder;

public class FailureInstanceTests
{
    private const string Hex64 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
    private const string Hex32 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
    private static readonly DateTimeOffset T0 = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    private static FailureSignatureMaterial Material(string testName = "MyTest", string? raw = "boom") => new()
    {
        TestIdentity = new FailureIdentity
        {
            AssemblyName = "ASM",
            ClassName = "NS.MyClass",
            TestName = testName
        },
        RawMessage = raw
    };

    private static (FailureSignatureMaterial Material, FailureSignatureDerivation Derivation) Derived(
        string testName = "MyTest", string? raw = "boom")
    {
        var material = Material(testName, raw);
        var derivation = new FailureSignatureService().Generate(material);
        return (material, derivation);
    }

    private static ExecutionSessionId Session() => ExecutionSessionId.Create($"ES-{Hex32}");

    // Stage 2.3.1+2.3.2 — composite id from signature + session
    [Fact]
    public void Create_ComposesInstanceId_FromFailureIdAndSession()
    {
        var (material, derivation) = Derived();
        var session = Session();

        var instance = FailureInstanceFactory.Create(material, derivation, session, T0);

        instance.InstanceId.Value.Should().Be($"FI|{derivation.FailureId.Value}|{session.Value}");
        instance.Session.Should().Be(session);
        instance.Signature.Should().Be(derivation.Signature);
        instance.FailureId.Should().Be(derivation.FailureId);
    }

    // Round-trip: the composite id re-parses into its parts
    [Fact]
    public void Create_InstanceId_RoundTripsThroughContract()
    {
        var (material, derivation) = Derived();
        var instance = FailureInstanceFactory.Create(material, derivation, Session(), T0);

        FailureInstanceId.TryParse(instance.InstanceId.Value, out var parsed).Should().BeTrue();
        parsed!.Failure.Should().Be(instance.FailureId);
        parsed.Session.Should().Be(instance.Session);
    }

    // Stage 2.3.3 — TestDefinitionId defaults to canonical full string
    [Fact]
    public void Create_TestDefinitionId_DefaultsToCanonicalIdentity()
    {
        var (material, derivation) = Derived("MyTest");
        var instance = FailureInstanceFactory.Create(material, derivation, Session(), T0);

        instance.TestDefinitionId.Should().Be("ASM:NS.MyClass.MyTest");
    }

    // Stage 2.3.3 — runner-reported definition override honored
    [Fact]
    public void Create_TestDefinitionOverride_Honored()
    {
        var (material, derivation) = Derived();
        var instance = FailureInstanceFactory.Create(
            material, derivation, Session(), T0, testDefinitionOverride: "  runner-def-42  ");

        instance.TestDefinitionId.Should().Be("runner-def-42");
    }

    [Fact]
    public void Create_WhitespaceOverride_FallsBackToCanonical()
    {
        var (material, derivation) = Derived();
        var instance = FailureInstanceFactory.Create(
            material, derivation, Session(), T0, testDefinitionOverride: "   ");

        instance.TestDefinitionId.Should().Be("ASM:NS.MyClass.MyTest");
    }

    // Stage 2.3.5 — occurrence time is the CALLER's observed time
    [Fact]
    public void Create_OccurredAt_IsCallerSupplied()
    {
        var (material, derivation) = Derived();
        var observed = new DateTimeOffset(2025, 1, 15, 8, 30, 0, TimeSpan.Zero);

        var instance = FailureInstanceFactory.Create(material, derivation, Session(), observed);

        instance.OccurredAtUtc.Should().Be(observed);   // never rewritten by the Core
    }

    // Same failure + two sessions = SAME signature, DIFFERENT instances
    // (the 2.4.5 recurrence-linking seed)
    [Fact]
    public void Create_SameFailureDifferentSessions_SameSignatureDifferentInstances()
    {
        var (material, derivation) = Derived("MyTest", "expected 512, actual 1024");

        var first = FailureInstanceFactory.Create(material, derivation,
            ExecutionSessionId.Create($"ES-{Hex32}"), T0);
        var second = FailureInstanceFactory.Create(material, derivation,
            ExecutionSessionId.Create($"ES-{'b'}{Hex32[1..]}"), T0.AddHours(1));

        first.Signature.Should().Be(second.Signature);           // same logical failure
        first.InstanceId.Should().NotBe(second.InstanceId);       // different occurrences
        first.OccurredAtUtc.Should().BeBefore(second.OccurredAtUtc);
    }

    // Different failure content in the same session = different instance
    [Fact]
    public void Create_DifferentFailureSameSession_DifferentInstances()
    {
        var session = Session();

        var (m1, d1) = Derived("MyTest", "expected 512, actual 1024");
        var (m2, d2) = Derived("MyTest", "expected 512, actual 512");

        var first = FailureInstanceFactory.Create(m1, d1, session, T0);
        var second = FailureInstanceFactory.Create(m2, d2, session, T0);

        first.Signature.Should().NotBe(second.Signature);
        first.InstanceId.Should().NotBe(second.InstanceId);
    }

    // Stage 2.3.4 — artifact association preserved
    [Fact]
    public void Create_SourceArtifact_Preserved()
    {
        var (material, derivation) = Derived();
        var instance = FailureInstanceFactory.Create(
            material, derivation, Session(), T0, sourceArtifact: "TestResults/run.trx");

        instance.SourceArtifact.Should().Be("TestResults/run.trx");
    }

    // Material retained — derivation stays reproducible from the instance
    [Fact]
    public void Create_MaterialRetained_SignatureReproducible()
    {
        var (material, derivation) = Derived("MyTest", "expected 512, actual 1024");
        var instance = FailureInstanceFactory.Create(material, derivation, Session(), T0);

        var regenerated = new FailureSignatureService().Generate(instance.Material);
        regenerated.Signature.Should().Be(instance.Signature);
    }

    // Full real flow — domain-evaluation material also becomes an instance
    [Fact]
    public void Create_DomainMaterial_FullFlow()
    {
        var material = FailureSignatureMaterialFactory.FromDomainEvaluation(
            new NormalizedEvaluationResult
            {
                SubControlId = "EVL-001.4",
                Status = CheckStatus.Fail,
                Reason = "expected 512, actual 1024",
                SourceTestId = "EventLogSizeCheck_Test"
            });
        var derivation = new FailureSignatureService().Generate(material);

        var instance = FailureInstanceFactory.Create(
            material, derivation, Session(), T0, sourceArtifact: "console");

        instance.InstanceId.Value.Should().StartWith("FI|F-");
        instance.Material.SubControlId.Should().Be("EVL-001.4");
        instance.Material.DomainStatus.Should().Be(CheckStatus.Fail);
    }

    // Contract violations fail fast
    [Fact]
    public void Create_NullArguments_Throw()
    {
        var (material, derivation) = Derived();

        Action nullMaterial = () => FailureInstanceFactory.Create(null!, derivation, Session(), T0);
        Action nullDerivation = () => FailureInstanceFactory.Create(material, null!, Session(), T0);
        Action nullSession = () => FailureInstanceFactory.Create(material, derivation, null!, T0);

        nullMaterial.Should().Throw<ArgumentNullException>();
        nullDerivation.Should().Throw<ArgumentNullException>();
        nullSession.Should().Throw<ArgumentNullException>();
    }
}