using System;
using ISCM.BugFinder.Core.Contracts;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class CanonicalIdentifierTests
{
    private const string Hex64 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
    private const string Hex32 = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";

    // H-01.2.3 — value equality is the whole point (X-005 fix)
    [Fact]
    public void FailureSignature_Create_ValidAndValueEqual()
    {
        var a = FailureSignature.Create($"FS-{Hex64}");
        var b = FailureSignature.Create($"FS-{Hex64}");

        a.Value.Should().Be($"FS-{Hex64}");
        a.Should().Be(b);
        (a == b).Should().BeTrue();
        a.ToString().Should().Be(a.Value);
    }

    [Fact]
    public void FailureSignature_RejectsInvalidFormats()
    {
        Action empty = () => FailureSignature.Create("  ");
        Action noPrefix = () => FailureSignature.Create(Hex64);
        Action shortHex = () => FailureSignature.Create($"FS-{Hex32}");
        Action nonHex = () => FailureSignature.Create("FS-" + new string('g', 64));

        empty.Should().Throw<ArgumentException>();
        noPrefix.Should().Throw<ArgumentException>();
        shortHex.Should().Throw<ArgumentException>();
        nonHex.Should().Throw<ArgumentException>();
    }

    // 1.2.1 / 1.2.3 / 1.2.4 / 1.2.8 / 1.2.9 — one contract, five prefixes
    [Fact]
    public void TryParse_PrefixedHexIdentifiers_RoundTrip()
    {
        FailureSignature.TryParse($"FS-{Hex64}", out var fs).Should().BeTrue();
        fs!.Value.Should().Be($"FS-{Hex64}");

        FailureId.TryParse($"F-{Hex64}", out var fid).Should().BeTrue();
        fid!.Value.Should().Be($"F-{Hex64}");

        EvidenceId.TryParse($"EV-{Hex32}", out var ev).Should().BeTrue();
        ev!.Value.Should().Be($"EV-{Hex32}");

        ExecutionSessionId.TryParse($"ES-{Hex32}", out var es).Should().BeTrue();
        es!.Value.Should().Be($"ES-{Hex32}");

        InvestigationId.TryParse($"INV-{Hex32}", out var inv).Should().BeTrue();
        inv!.Value.Should().Be($"INV-{Hex32}");

        FailureSignature.TryParse("nope", out _).Should().BeFalse();
        EvidenceId.TryParse(null, out _).Should().BeFalse();
    }

    // H-01.2.10 — git SHA (full + short), hex-only
    [Fact]
    public void RevisionId_ShaValidation()
    {
        var full = RevisionId.Create("86e0b257cc0d4c957f0120a1ea201ed8d3ebc067");
        full.Value.Should().Be("86e0b257cc0d4c957f0120a1ea201ed8d3ebc067");

        var shortSha = RevisionId.Create("86e0b25");
        shortSha.Value.Should().Be("86e0b25");

        Action tooShort = () => RevisionId.Create("86e0b2");
        Action nonHex = () => RevisionId.Create("86e0b2z-not-hex-at-all!!");
        tooShort.Should().Throw<ArgumentException>();
        nonHex.Should().Throw<ArgumentException>();
    }

    // H-01.2.2 — composite: signature instance = failure + session
    [Fact]
    public void FailureInstanceId_ComposeParseAndEquality()
    {
        var failure = FailureId.Create($"F-{Hex64}");
        var session = ExecutionSessionId.Create($"ES-{Hex32}");

        var instance = FailureInstanceId.Create(failure, session);
        instance.Value.Should().Be($"FI|F-{Hex64}|ES-{Hex32}");

        FailureInstanceId.TryParse(instance.Value, out var parsed).Should().BeTrue();
        parsed.Should().Be(instance);
        parsed!.Failure.Should().Be(failure);
        parsed.Session.Should().Be(session);
    }

    [Fact]
    public void FailureInstanceId_RejectsMalformed()
    {
        FailureInstanceId.TryParse("FI|not-an-id|ES-x", out _).Should().BeFalse();
        FailureInstanceId.TryParse("FI|only-two", out _).Should().BeFalse();
        FailureInstanceId.TryParse("XX|F-1|ES-1", out _).Should().BeFalse();
        FailureInstanceId.TryParse(null, out _).Should().BeFalse();
    }

    // H-01.2.6 — must accept exactly the BF-13.4 StableKey format
    [Fact]
    public void SymbolKey_ValidatesStableKeyContract()
    {
        var key = SymbolKey.FromStableKey("M|ISCM|Check.Evaluate()");
        key.Value.Should().Be("M|ISCM|Check.Evaluate()");

        SymbolKey.TryParse("T|Lib|Sample.Calc", out _).Should().BeTrue();
        SymbolKey.TryParse("X|Lib|Sample.Calc", out _).Should().BeFalse();
        SymbolKey.TryParse("M|only-two", out _).Should().BeFalse();

        Action invalid = () => SymbolKey.FromStableKey("X|Lib|Nope");
        invalid.Should().Throw<ArgumentException>();
    }

    // H-01.2.5 — symbol / file / legacy classification (KBF-14-001 path seed)
    [Fact]
    public void TargetKey_ClassifiesSymbolFileAndOther()
    {
        var symbol = TargetKey.FromSymbol(SymbolKey.FromStableKey("M|ISCM|Check.Evaluate()"));
        symbol.Kind.Should().Be(TargetKeyKind.Symbol);

        var file = TargetKey.FromFile(@"Sources\Check.cs");
        file.Value.Should().Be("FILE|Sources/Check.cs");
        file.Kind.Should().Be(TargetKeyKind.File);

        var raw = TargetKey.FromRaw("some-legacy-key");
        raw.Kind.Should().Be(TargetKeyKind.Other);
    }

    // H-01.2.7 — file + optional line, backslash normalized
    [Fact]
    public void LocationId_WithAndWithoutLine()
    {
        var withLine = LocationId.Create(@"Calc\Check.cs", 42);
        withLine.Value.Should().Be("LOC|Calc/Check.cs|L42");
        LocationId.TryParse("LOC|Calc/Check.cs|L42", out _).Should().BeTrue();

        var noLine = LocationId.Create("Calc/Check.cs");
        noLine.Value.Should().Be("LOC|Calc/Check.cs");
        LocationId.TryParse("LOC|Calc/Check.cs", out _).Should().BeTrue();

        LocationId.TryParse("WRONG|Calc.cs", out _).Should().BeFalse();
    }

    [Fact]
    public void Identifiers_ToString_EqualsValue()
    {
        var sig = FailureSignature.Create($"FS-{Hex64}");
        var sha = RevisionId.Create("86e0b257cc0d4c957f0120a1ea201ed8d3ebc067");
        var loc = LocationId.Create("Calc.cs", 7);

        sig.ToString().Should().Be(sig.Value);
        sha.ToString().Should().Be(sha.Value);
        loc.ToString().Should().Be(loc.Value);
    }
}