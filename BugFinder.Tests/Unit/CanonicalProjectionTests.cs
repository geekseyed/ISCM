using System;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CanonicalProjectionTests
{
    // H-01.6.1 — canonical ToFullString format parses exactly
    [Fact]
    public void FailureIdentity_FromCanonicalFormat_ExactTriple()
    {
        var identity = FailureIdentityProjection.FromInput(
            new FailureIdentityInput { TestIdentity = "ASM:MyClass.MyTest" });

        identity.AssemblyName.Should().Be("ASM");
        identity.ClassName.Should().Be("MyClass");
        identity.TestName.Should().Be("MyTest");
    }

    // No assembly in the string -> stays EMPTY (no fabrication)
    [Fact]
    public void FailureIdentity_FromNamespaceQualified_NoAssemblyFabricated()
    {
        var identity = FailureIdentityProjection.FromInput(
            new FailureIdentityInput { TestIdentity = "ISCM.Tests.EventLogSizeCheck_Test" });

        identity.AssemblyName.Should().BeEmpty();
        identity.ClassName.Should().Be("ISCM.Tests");
        identity.TestName.Should().Be("EventLogSizeCheck_Test");
    }

    [Fact]
    public void FailureIdentity_FromBareTestName_OnlyTestKnown()
    {
        var identity = FailureIdentityProjection.FromInput(
            new FailureIdentityInput { TestIdentity = "SoloTest" });

        identity.AssemblyName.Should().BeEmpty();
        identity.ClassName.Should().BeEmpty();
        identity.TestName.Should().Be("SoloTest");
    }

    [Fact]
    public void FailureIdentity_FromEmptyInput_EmptyIdentity()
    {
        var identity = FailureIdentityProjection.FromInput(new FailureIdentityInput { TestIdentity = "  " });

        identity.AssemblyName.Should().BeEmpty();
        identity.ClassName.Should().BeEmpty();
        identity.TestName.Should().BeEmpty();
    }

    // H-01.6.6 — canonical round-trip is exact + category passthrough
    [Fact]
    public void FailureIdentity_RoundTrip_ExactAndCarriesMetadata()
    {
        var original = new FailureIdentity
        {
            AssemblyName = "ASM",
            ClassName = "NS.MyClass",
            TestName = "MyTest"
        };

        var input = FailureIdentityProjection.ToInput(original,
            failureCategory: "Assertion:Equality", failureSignature: null);

        input.TestIdentity.Should().Be("ASM:NS.MyClass.MyTest");
        input.FailureCategory.Should().Be("Assertion:Equality");

        var restored = FailureIdentityProjection.FromInput(input);
        restored.AssemblyName.Should().Be(original.AssemblyName);
        restored.ClassName.Should().Be(original.ClassName);
        restored.TestName.Should().Be(original.TestName);
    }

    // H-01.6.2 — chain view round-trip preserves fields, drops IsPrimary
    [Fact]
    public void SourceLocation_ChainViewRoundTrip_FieldsPreserved()
    {
        var canonical = new SourceLocation
        {
            FilePath = "Calc.cs",
            LineNumber = 42,
            MethodName = "Evaluate"
        };

        var chainView = SourceLocationProjection.ToChainView(canonical, isPrimary: true);
        chainView.FilePath.Should().Be("Calc.cs");
        chainView.LineNumber.Should().Be(42);
        chainView.MethodName.Should().Be("Evaluate");
        chainView.IsPrimary.Should().BeTrue();

        var restored = SourceLocationProjection.ToCanonical(chainView);
        restored.FilePath.Should().Be(canonical.FilePath);
        restored.LineNumber.Should().Be(canonical.LineNumber);
        restored.MethodName.Should().Be(canonical.MethodName);
    }

    // H-01.6.6 — both views of the SAME location yield ONE LocationId
    [Fact]
    public void SourceLocation_BothViews_SameLocationId()
    {
        var canonical = new SourceLocation { FilePath = "Calc.cs", LineNumber = 42 };
        var chainView = SourceLocationProjection.ToChainView(canonical);

        var fromCanonical = SourceLocationProjection.ToLocationId(canonical);
        var fromChain = SourceLocationProjection.ToLocationId(chainView);

        fromCanonical.Should().NotBeNull();
        fromCanonical.Should().Be(fromChain);
        fromCanonical!.ToString().Should().Be("LOC|Calc.cs|L42");
    }

    // Method-only knowledge -> null identity (no fabrication)
    [Fact]
    public void SourceLocation_MethodOnly_LocationIdIsNull()
    {
        var methodOnly = new SourceLocation { MethodName = "Evaluate" };
        SourceLocationProjection.ToLocationId(methodOnly).Should().BeNull();
    }

    // H-01.6.3+1.6.6 — same ElementId across ALL suspicious views = ONE TargetKey
    [Fact]
    public void SuspiciousTargets_SameElement_SameTargetKeyAcrossAllModels()
    {
        const string element = "Calc.cs:Evaluate:42";

        var from12_9 = SuspiciousTargetProjection.TargetKeyOf(new RankedFaultCandidate { ElementId = element });
        var from12_10 = SuspiciousTargetProjection.TargetKeyOf(new EvidenceRankedCandidate { ElementId = element });
        var from12 = SuspiciousTargetProjection.TargetKeyOf(new SuspiciousLocation { ElementId = element });
        var from15_7 = SuspiciousTargetProjection.TargetKeyOf(new ExperimentalSuspiciousness { ElementId = element });
        var from14_2 = SuspiciousTargetProjection.TargetKeyOf(new CorrelatedTarget { TargetKey = element });

        from12_9.Should().Be(from12_10);
        from12_10.Should().Be(from12);
        from12.Should().Be(from15_7);
        from15_7.Should().Be(from14_2);
        from14_2.Kind.Should().Be(TargetKeyKind.Other);
    }

    // Canonical FILE| keys flow through classification unchanged
    [Fact]
    public void SuspiciousTargets_FileKey_ClassifiedAsFile()
    {
        var key = SuspiciousTargetProjection.TargetKeyOf(
            new CorrelatedTarget { TargetKey = "FILE|Calc.cs" });

        key.Kind.Should().Be(TargetKeyKind.File);
        key.Value.Should().Be("FILE|Calc.cs");
    }

    // H-01.6.6 — same File+Line across suspicious views = ONE LocationId
    [Fact]
    public void SuspiciousTargets_SameElementLocation_SameLocationIdAcrossModels()
    {
        var from12_10 = SuspiciousTargetProjection.LocationIdOf(
            new EvidenceRankedCandidate { ElementId = "E1", FilePath = "Calc.cs", LineNumber = 42 });
        var from12_9 = SuspiciousTargetProjection.LocationIdOf(
            new RankedFaultCandidate { ElementId = "E1", FilePath = "Calc.cs", LineNumber = 42 });
        var from12 = SuspiciousTargetProjection.LocationIdOf(
            new SuspiciousLocation { ElementId = "E1", FilePath = "Calc.cs", LineNumber = 42 });
        var from15_7 = SuspiciousTargetProjection.LocationIdOf(
            new ExperimentalSuspiciousness { ElementId = "E1", FilePath = "Calc.cs", LineNumber = 42 });

        from12_10.Should().Be(from12_9);
        from12_9.Should().Be(from12);
        from12.Should().Be(from15_7);
        from12_10!.ToString().Should().Be("LOC|Calc.cs|L42");
    }

    [Fact]
    public void SuspiciousTargets_WithoutLocation_LocationIdIsNull()
    {
        SuspiciousTargetProjection.LocationIdOf(
            new EvidenceRankedCandidate { ElementId = "E1" }).Should().BeNull();
    }

    // H-01.6.1 — history record projects honestly (test name only)
    [Fact]
    public void FailureRecord_ProjectsToIdentityAndLocation()
    {
        var record = new FailureRecord
        {
            FailureSignature = "sig",
            TestName = "MyTest",
            FilePath = "Calc.cs",
            LineNumber = 42
        };

        var identity = FailureRecordProjection.ToIdentity(record);
        identity.TestName.Should().Be("MyTest");
        identity.AssemblyName.Should().BeEmpty();
        identity.ClassName.Should().BeEmpty();

        var location = FailureRecordProjection.ToLocationId(record);
        location!.ToString().Should().Be("LOC|Calc.cs|L42");
    }

    // Contract violations fail fast
    [Fact]
    public void Projections_NullInputs_Throw()
    {
        Action nullInput = () => FailureIdentityProjection.FromInput(null!);
        Action nullIdentity = () => FailureIdentityProjection.ToInput(null!);
        Action nullChain = () => SourceLocationProjection.ToCanonical(null!);
        Action nullCanonical = () => SourceLocationProjection.ToChainView(null!);
        Action nullRecord = () => FailureRecordProjection.ToIdentity(null!);
        Action nullTarget = () => SuspiciousTargetProjection.TargetKeyOf((CorrelatedTarget)null!);

        nullInput.Should().Throw<ArgumentNullException>();
        nullIdentity.Should().Throw<ArgumentNullException>();
        nullChain.Should().Throw<ArgumentNullException>();
        nullCanonical.Should().Throw<ArgumentNullException>();
        nullRecord.Should().Throw<ArgumentNullException>();
        nullTarget.Should().Throw<ArgumentNullException>();
    }
}