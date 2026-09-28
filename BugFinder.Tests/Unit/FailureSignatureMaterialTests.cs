using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.Domain.Enums;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class FailureSignatureMaterialTests
{
    // Empty material = honest empty; nothing fabricated
    [Fact]
    public void EmptyMaterial_HasNoKnowledge_AndDefaults()
    {
        var material = new FailureSignatureMaterial();

        material.HasAnyKnowledge.Should().BeFalse();
        material.TestIdentity.TestName.Should().BeEmpty();
        material.TestIdentity.AssemblyName.Should().BeEmpty();
        material.AssertionType.Should().BeNull();
        material.ExceptionTypeName.Should().BeNull();
        material.InnerExceptionTypeNames.Should().BeEmpty();
        material.SubControlId.Should().BeNull();
        material.DomainStatus.Should().BeNull();
        material.Location.Should().BeNull();
        material.RawMessage.Should().BeNull();
        material.EnvironmentFingerprint.Should().BeNull();
    }

    // Adapter — raw message preferred over processed (BF-01 GAP-01)
    [Fact]
    public void FromTestResult_MapsIdentity_AndPrefersRawMessage()
    {
        var result = new NormalizedTestResult
        {
            Identity = new FailureIdentity
            {
                AssemblyName = "ASM",
                ClassName = "NS.MyClass",
                TestName = "MyTest"
            },
            ErrorMessage = "processed",
            RawErrorMessage = "  raw original  "
        };

        var material = FailureSignatureMaterialFactory.FromTestResult(result);

        material.TestIdentity.ToFullString().Should().Be("ASM:NS.MyClass.MyTest");
        material.RawMessage.Should().Be("  raw original  ");   // raw preserved verbatim
        material.HasAnyKnowledge.Should().BeTrue();
    }

    // Adapter — raw missing: falls back to processed, trimmed
    [Fact]
    public void FromTestResult_RawMissing_FallsBackToProcessed()
    {
        var result = new NormalizedTestResult
        {
            Identity = new FailureIdentity { TestName = "T1" },
            ErrorMessage = "  processed message  "
        };

        var material = FailureSignatureMaterialFactory.FromTestResult(result);

        material.RawMessage.Should().Be("processed message");
    }

    // No fabrication — no message known stays null
    [Fact]
    public void FromTestResult_NoMessages_RawMessageStaysNull()
    {
        var material = FailureSignatureMaterialFactory.FromTestResult(
            new NormalizedTestResult { Identity = new FailureIdentity { TestName = "T1" } });

        material.RawMessage.Should().BeNull();
        material.ExceptionTypeName.Should().BeNull();   // H-03 extraction later
    }

    // Adapter — domain evaluation maps SubControl/Status/Reason
    [Fact]
    public void FromDomainEvaluation_MapsSubControlStatusAndReason()
    {
        var result = new NormalizedEvaluationResult
        {
            SubControlId = "EVL-001.4",
            Status = CheckStatus.Fail,
            Reason = "expected 512, actual 1024",
            SourceTestId = "EventLogSizeCheck_Test"
        };

        var material = FailureSignatureMaterialFactory.FromDomainEvaluation(result);

        material.SubControlId.Should().Be("EVL-001.4");
        material.DomainStatus.Should().Be(CheckStatus.Fail);
        material.RawMessage.Should().Be("expected 512, actual 1024");
        material.HasAnyKnowledge.Should().BeTrue();
    }

    // No fabrication — SourceTestId becomes TestName ONLY; assembly/class stay empty
    [Fact]
    public void FromDomainEvaluation_SourceTestId_BecomesTestName_AssemblyNeverFabricated()
    {
        var material = FailureSignatureMaterialFactory.FromDomainEvaluation(
            new NormalizedEvaluationResult { SubControlId = "EVL-001.4", Status = CheckStatus.Error });

        material.TestIdentity.TestName.Should().BeEmpty();
        material.TestIdentity.AssemblyName.Should().BeEmpty();
        material.TestIdentity.ClassName.Should().BeEmpty();
        material.DomainStatus.Should().Be(CheckStatus.Error);
    }

    // H-02.1.3 — inner exception chain preserved in order
    [Fact]
    public void Material_ExceptionChain_PreservedInOrder()
    {
        var material = new FailureSignatureMaterial
        {
            ExceptionTypeName = "System.InvalidOperationException",
            InnerExceptionTypeNames = new[]
            {
                "System.IO.IOException",
                "System.ArgumentException"
            }
        };

        material.ExceptionTypeName.Should().Contain("InvalidOperation");
        material.InnerExceptionTypeNames.Should().ContainInOrder(
            "System.IO.IOException", "System.ArgumentException");
    }

    // H-02.1.5 — canonical SourceLocation (H-01.6) reused, not duplicated
    [Fact]
    public void Material_Location_UsesCanonicalSourceLocation()
    {
        var material = new FailureSignatureMaterial
        {
            Location = new SourceLocation { FilePath = "Calc.cs", LineNumber = 42, MethodName = "Evaluate" }
        };

        material.Location!.FilePath.Should().Be("Calc.cs");
        material.Location.LineNumber.Should().Be(42);
        SourceLocationProjection.ToLocationId(material.Location)!
            .ToString().Should().Be("LOC|Calc.cs|L42");   // H-01.6/H-01.2 interop
    }

    // Contract — session/occurrence belong to the INSTANCE (H-02.3), never the material
    [Fact]
    public void Material_SessionAndOccurrence_AreStructurallyAbsent()
    {
        typeof(FailureSignatureMaterial).GetProperty("SessionId").Should().BeNull(
            "ExecutionSessionId belongs to the failure INSTANCE (H-02.3.2)");
        typeof(FailureSignatureMaterial).GetProperty("OccurredAt").Should().BeNull(
            "occurrence time belongs to the failure INSTANCE (H-02.3.5)");
    }

    // HasAnyKnowledge reflects every section
    [Fact]
    public void HasAnyKnowledge_ReflectsEachSection()
    {
        new FailureSignatureMaterial { AssertionType = "Equality" }
            .HasAnyKnowledge.Should().BeTrue();
        new FailureSignatureMaterial { SubControlId = "EVL-1" }
            .HasAnyKnowledge.Should().BeTrue();
        new FailureSignatureMaterial { DomainStatus = CheckStatus.Unknown }
            .HasAnyKnowledge.Should().BeTrue();
        new FailureSignatureMaterial { EnvironmentFingerprint = "win-x64" }
            .HasAnyKnowledge.Should().BeTrue();
        new FailureSignatureMaterial { InnerExceptionTypeNames = new[] { "System.Exception" } }
            .HasAnyKnowledge.Should().BeTrue();
    }

    // Contract violations fail fast
    [Fact]
    public void Factory_NullArguments_Throw()
    {
        Action nullTest = () => FailureSignatureMaterialFactory.FromTestResult(null!);
        Action nullDomain = () => FailureSignatureMaterialFactory.FromDomainEvaluation(null!);

        nullTest.Should().Throw<ArgumentNullException>();
        nullDomain.Should().Throw<ArgumentNullException>();
    }
}