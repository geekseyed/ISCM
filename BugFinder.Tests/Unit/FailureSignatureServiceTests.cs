using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using FluentAssertions;
using Xunit;
using ISCM.BugFinder.Core.Services;
using ISCM.Domain.Enums;

namespace ISCM.Tests.Unit.BugFinder;

public class FailureSignatureServiceTests
{
    private readonly FailureSignatureService _service = new();

    private static FailureSignatureMaterial TestMaterial(string testName = "MyTest", string? raw = null) => new()
    {
        TestIdentity = new FailureIdentity
        {
            AssemblyName = "ASM",
            ClassName = "NS.MyClass",
            TestName = testName
        },
        RawMessage = raw
    };

    // 2.2.7 — deterministic: same material, two instances, one signature
    [Fact]
    public void Generate_Deterministic_SameMaterialSameSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "assert failed"));
        var b = _service.Generate(TestMaterial("T1", "assert failed"));

        a.Signature.Should().Be(b.Signature);
        a.FailureId.Should().Be(b.FailureId);
        a.CanonicalForm.Should().Be(b.CanonicalForm);
    }

    // Format contract: FS-<64 lowercase hex>
    [Fact]
    public void Generate_SignatureFormat_FS_Prefix64Hex()
    {
        var derivation = _service.Generate(TestMaterial("T1", "boom"));

        derivation.Signature.Value.Should().MatchRegex(@"^FS-[0-9a-f]{64}$");
        derivation.FailureId.Value.Should().MatchRegex(@"^F-[0-9a-f]{64}$");
    }

    // KBF-01-012 — different test name = different failure
    [Fact]
    public void Generate_DifferentTestName_DifferentSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "same message"));
        var b = _service.Generate(TestMaterial("T2", "same message"));

        a.Signature.Should().NotBe(b.Signature);
    }

    // KBF-01-012 core — same test, DIFFERENT assertion = different failure
    [Fact]
    public void Generate_SameTest_DifferentAssertionType_DifferentSignature()
    {
        var a = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            AssertionType = "Equality",
            RawMessage = "values differ"
        });
        var b = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            AssertionType = "Collection",
            RawMessage = "values differ"
        });

        a.Signature.Should().NotBe(b.Signature);
    }

    // 2.2.5 — volatile run-to-run jitter is absorbed
    [Fact]
    public void Generate_VolatileNumberJitter_SameSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "operation took 1237 ms"));
        var b = _service.Generate(TestMaterial("T1", "operation took 1180 ms"));

        a.Signature.Should().Be(b.Signature);   // both bucket to <N~1024>
    }

    // 2.2.6 — meaningful magnitude change is PRESERVED
    [Fact]
    public void Generate_MeaningfulMagnitudeChange_DifferentSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "expected 512, actual 1024"));
        var b = _service.Generate(TestMaterial("T1", "expected 512, actual 512"));

        a.Signature.Should().NotBe(b.Signature);   // 1024 and 512 differ by bucket
    }

    // 2.2.5 — GUID / hex / timestamp volatility absorbed
    [Fact]
    public void Generate_GuidsHexTimestamps_Absorbed()
    {
        var a = _service.Generate(TestMaterial("T1",
            "request 3f2b8a1c-9d4e-4f5a-b6c7-d8e9f0a1b2c3 at 2026-09-27 10:00:00 failed"));
        var b = _service.Generate(TestMaterial("T1",
            "request 99887766-1122-4334-5566-778899aabbcc at 2030-01-01T23:59 failed"));

        a.Signature.Should().Be(b.Signature);
    }

    // 2.2.5 — path separators normalized (backslash == slash)
    [Fact]
    public void Generate_PathSeparatorVariants_SameSignature()
    {
        var a = _service.Generate(TestMaterial("T1", @"file C:\Repo\Calc.cs not found"));
        var b = _service.Generate(TestMaterial("T1", "file C:/Repo/Calc.cs not found"));

        a.Signature.Should().Be(b.Signature);
    }

    // 2.2.3 — different exception type = different failure
    [Fact]
    public void Generate_DifferentExceptionType_DifferentSignature()
    {
        var a = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            ExceptionTypeName = "System.InvalidOperationException"
        });
        var b = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            ExceptionTypeName = "System.TimeoutException"
        });

        a.Signature.Should().NotBe(b.Signature);
    }

    // 2.2.3 — inner chain difference is preserved
    [Fact]
    public void Generate_InnerChainDifference_DifferentSignature()
    {
        var material = () => new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            ExceptionTypeName = "System.InvalidOperationException"
        };

        var a = _service.Generate(material().InnerExceptionTypeNames is { } _ // placeholder
            ? material() : material());
        var withChain = new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            ExceptionTypeName = "System.InvalidOperationException",
            InnerExceptionTypeNames = new[] { "System.IO.IOException" }
        };

        a.Signature.Should().NotBe(_service.Generate(withChain).Signature);
    }

    // 2.1.4 — same SubControl, different domain status = different failure
    [Fact]
    public void Generate_DomainStatusDifference_DifferentSignature()
    {
        var a = _service.Generate(new FailureSignatureMaterial { SubControlId = "EVL-001.4", DomainStatus = CheckStatus.Fail });
        var b = _service.Generate(new FailureSignatureMaterial { SubControlId = "EVL-001.4", DomainStatus = CheckStatus.Error });

        a.Signature.Should().NotBe(b.Signature);
    }

    // H-01.2 derivation contract — FailureId shares the signature's hex
    [Fact]
    public void Generate_FailureId_DerivedFromSameHash()
    {
        var derivation = _service.Generate(TestMaterial("T1", "boom"));

        derivation.FailureId.Value.Should().StartWith("F-");
        derivation.FailureId.Value.Substring(2)
            .Should().Be(derivation.Signature.Value.Substring(3));
    }

    // H-01.4 at signature level — empty message vs NO message are distinct
    [Fact]
    public void Generate_EmptyMessageVsAbsentMessage_DifferentSignatures()
    {
        var emptyMessage = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            RawMessage = ""
        });
        var absentMessage = _service.Generate(new FailureSignatureMaterial
        {
            TestIdentity = TestMaterial().TestIdentity,
            RawMessage = null
        });

        emptyMessage.Signature.Should().NotBe(absentMessage.Signature);
        emptyMessage.CanonicalForm.Should().Contain("message=\n");
        absentMessage.CanonicalForm.Should().Contain("message=<ABSENT>");
    }

    // Canonical form: versioned, section-labeled, audit-ready
    [Fact]
    public void Generate_CanonicalForm_VersionedAndLabeled()
    {
        var derivation = _service.Generate(TestMaterial("T1", "boom"));

        derivation.CanonicalForm.Should().StartWith("sigv1|");
        derivation.CanonicalForm.Should().Contain("test=ASM|NS.MyClass|T1");
        derivation.CanonicalForm.Should().Contain("assertion=<ABSENT>");
        derivation.CanonicalForm.Should().Contain("message=boom");
    }

    // Documented decision — case is PRESERVED (pinned)
    [Fact]
    public void Generate_CasePreserved_DifferentSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "Value was Null"));
        var b = _service.Generate(TestMaterial("T1", "value was null"));

        a.Signature.Should().NotBe(b.Signature);   // documented v1 decision
    }

    // 2.2.5 — whitespace/padding absorbed
    [Fact]
    public void Generate_WhitespaceAndPadding_SameSignature()
    {
        var a = _service.Generate(TestMaterial("T1", "failed   with\tcode  7"));
        var b = _service.Generate(TestMaterial("T1", "failed with code 7"));

        a.Signature.Should().Be(b.Signature);
    }

    // Cross-session recurrence seed — material has no session; two
    // "sessions" (fresh instances) with the same content link by signature
    [Fact]
    public void Generate_CrossSessionRecurrenceSeed_SameSignature()
    {
        var sessionA = FailureSignatureMaterialFactory.FromTestResult(new NormalizedTestResult
        {
            Identity = new FailureIdentity { AssemblyName = "A", ClassName = "C", TestName = "T" },
            RawErrorMessage = "expected 512, actual 1024"
        });
        var sessionB = FailureSignatureMaterialFactory.FromTestResult(new NormalizedTestResult
        {
            Identity = new FailureIdentity { AssemblyName = "A", ClassName = "C", TestName = "T" },
            RawErrorMessage = "expected 512, actual 1024"
        });

        var a = _service.Generate(sessionA);
        var b = _service.Generate(sessionB);

        a.Signature.Should().Be(b.Signature);   // H-02.4.5 will link these
    }

    // No fabrication — zero knowledge cannot produce a signature
    [Fact]
    public void Generate_EmptyMaterial_Throws()
    {
        Action act = () => _service.Generate(new FailureSignatureMaterial());
        act.Should().Throw<ArgumentException>()
            .WithMessage("*zero knowledge*");
    }

    [Fact]
    public void Generate_NullMaterial_Throws()
    {
        Action act = () => _service.Generate(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}