using System;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;
using ISCM.BugFinder.Core.Services;
using FluentAssertions;
using Xunit;

namespace ISCM.Tests.Unit.BugFinder;

public class TypedIdentityMigrationTests
{
    private readonly EvidenceFusionService _fusion = new();
    private readonly EvidenceConsistencyService _consistency = new();

    // ---------- JoinKeyNormalization (Stage 1.7.1/1.7.2 rules) ----------

    [Fact]
    public void Normalization_RawKey_TrimsAndSlashNormalizesFileKeys()
    {
        JoinKeyNormalization.NormalizeRawKey("  M|R|Foo()  ").Should().Be("M|R|Foo()");
        JoinKeyNormalization.NormalizeRawKey(@"FILE|Calc\Check.cs").Should().Be("FILE|Calc/Check.cs");
        JoinKeyNormalization.NormalizeRawKey("legacy").Should().Be("legacy");
        JoinKeyNormalization.NormalizeRawKey(null).Should().BeEmpty();
        JoinKeyNormalization.NormalizeRawKey("   ").Should().BeEmpty();
    }

    [Fact]
    public void Normalization_Path_TrimsAndSlash()
    {
        JoinKeyNormalization.NormalizePath(@" Calc\Check.cs ").Should().Be("Calc/Check.cs");
        JoinKeyNormalization.NormalizePath("a/b/c.cs").Should().Be("a/b/c.cs");
    }

    [Fact]
    public void Normalization_ResolveGroupKey_Rules()
    {
        JoinKeyNormalization.ResolveGroupKey(" M|R|X() ", null).Should().Be("M|R|X()");
        JoinKeyNormalization.ResolveGroupKey(null, @"Calc\Check.cs").Should().Be("FILE|Calc/Check.cs");
        // whitespace-only symbol = ABSENT (falls through to file - never its own group)
        JoinKeyNormalization.ResolveGroupKey("   ", @"Calc\Check.cs").Should().Be("FILE|Calc/Check.cs");
        JoinKeyNormalization.ResolveGroupKey(null, null).Should().Be("FILE|unknown");
        JoinKeyNormalization.ResolveGroupKey(null, "  ").Should().Be("FILE|unknown");
    }

    // ---------- TypedJoinIndex (Stage 1.7.3 typed adoption) ----------

    [Fact]
    public void JoinIndex_ClassifiesKinds()
    {
        var index = TypedJoinIndex.Build(new[] { "M|ISCM|Foo()", "FILE|Calc.cs", "legacy-key" });

        index.Entries.Should().HaveCount(3);
        index.CountByKind(TargetKeyKind.Symbol).Should().Be(1);
        index.CountByKind(TargetKeyKind.File).Should().Be(1);
        index.CountByKind(TargetKeyKind.Other).Should().Be(1);
        index.Diagnostics.Should().BeEmpty();
    }

    [Fact]
    public void JoinIndex_SymbolEntries_ParseAsTypedSymbolKey()
    {
        var index = TypedJoinIndex.Build(new[] { "M|ISCM|Foo()" });

        index.Entries[0].Kind.Should().Be(TargetKeyKind.Symbol);
        SymbolKey.TryParse(index.Entries[0].NormalizedKey, out _).Should().BeTrue();
        index.Entries[0].Key.Value.Should().Be("M|ISCM|Foo()");
    }

    [Fact]
    public void JoinIndex_CaseVariants_FlaggedButNotMerged()
    {
        var index = TypedJoinIndex.Build(new[] { "M|R|Foo()", "m|r|foo()" });

        index.Entries.Should().HaveCount(2);   // grouping preserves case (H-07.6 deferral)
        index.Diagnostics.Should().Contain(d => d.Contains("case-variant"));
    }

    [Fact]
    public void JoinIndex_EmptyKeys_SkippedWithDiagnostic()
    {
        var index = TypedJoinIndex.Build(new string?[] { "M|R|Foo()", "  ", null });

        index.Entries.Should().HaveCount(1);
        index.Diagnostics.Should().Contain(d => d.Contains("empty join key"));
    }

    [Fact]
    public void JoinIndex_CanJoin_AfterNormalization()
    {
        var index = TypedJoinIndex.Build(new[] { @"FILE|Calc\Check.cs" });

        index.CanJoin(@"FILE|Calc\Check.cs ", "FILE|Calc/Check.cs").Should().BeTrue();
        index.CanJoin("FILE|Calc/Check.cs", "FILE|Other.cs").Should().BeFalse();
        index.CanJoin("", "FILE|x").Should().BeFalse();
    }

    [Fact]
    public void JoinIndex_TryGetByRaw_PaddedLookupFindsNormalizedEntry()
    {
        var index = TypedJoinIndex.Build(new[] { "M|ISCM|Foo()" });

        index.TryGetByRaw("  M|ISCM|Foo()  ", out var entry).Should().BeTrue();
        entry!.NormalizedKey.Should().Be("M|ISCM|Foo()");
        entry.Kind.Should().Be(TargetKeyKind.Symbol);
    }

    // ---------- Fusion adoption (Stage 1.7.6 - real fixes) ----------

    // THE backslash/slash split bug: same file, two path forms,
    // pre-H-01.7 fused into TWO targets - now ONE.
    [Fact]
    public void Fuse_BackslashAndSlashPathVariants_FuseIntoOneGroup()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Regression,  RawStrength = 0.5, TargetFilePath = @"Calc\Check.cs" },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.TestFailure, RawStrength = 0.7, TargetFilePath = "Calc/Check.cs" }
        };

        var fused = _fusion.Fuse(inputs);

        fused.Items.Should().ContainSingle();
        fused.Items[0].TargetKey.Should().Be("FILE|Calc/Check.cs");
        fused.Items[0].Sources.Should().HaveCount(2);
        fused.JoinDiagnostics.Should().BeEmpty();   // they genuinely joined - no hazard
    }

    [Fact]
    public void Fuse_CleanInput_NoJoinDiagnostics()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,    RawStrength = 0.8, TargetSymbolKey = "M|R|Compute()" },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Coverage, RawStrength = 0.6, TargetSymbolKey = "M|R|Compute()" }
        };

        var fused = _fusion.Fuse(inputs);

        fused.Items.Should().ContainSingle();
        fused.JoinDiagnostics.Should().BeEmpty();
    }

    [Fact]
    public void Fuse_CaseVariantSymbolKeys_TwoGroupsPlusDiagnostic()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,      RawStrength = 0.8, TargetSymbolKey = "M|R|Compute()" },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Historical, RawStrength = 0.3, TargetSymbolKey = "m|r|compute()" }
        };

        var fused = _fusion.Fuse(inputs);

        fused.Items.Should().HaveCount(2);   // case preserved by design
        fused.JoinDiagnostics.Should().Contain(d => d.Contains("case-variant"));
    }

    [Fact]
    public void Fuse_UntargetedEvidence_DiagnosticEmitted()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Runtime, RawStrength = 0.4 }
        };

        var fused = _fusion.Fuse(inputs);

        fused.Items.Should().ContainSingle();
        fused.Items[0].TargetKey.Should().Be("FILE|unknown");
        fused.JoinDiagnostics.Should().Contain(d => d.Contains("FILE|unknown"));
    }

    // ---------- Cross-service agreement (the X-005 join-safety fix) ----------

    // Pre-H-01.7: Fusion normalized padded keys, Consistency/Conflict
    // trusted raw strings - the same event could split differently per
    // service. Now all three share one group-membership truth.
    [Fact]
    public void Consistency_And_Fusion_Agree_ForPaddedSymbolKeys()
    {
        var inputs = new[]
        {
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Stack,    RawStrength = 0.8, TargetSymbolKey = " M|R|Compute() " },
            new FusionEvidenceInput { SourceType = CandidateEvidenceType.Coverage, RawStrength = 0.6, TargetSymbolKey = "M|R|Compute()" }
        };

        var fused = _fusion.Fuse(inputs);
        fused.Items.Should().ContainSingle();
        fused.Items[0].TargetKey.Should().Be("M|R|Compute()");

        var consistency = _consistency.Evaluate(inputs, fused);
        consistency.Targets.Should().ContainSingle();
        consistency.Targets[0].TargetKey.Should().Be("M|R|Compute()");
        consistency.Targets[0].CrossSource.Should().Be(CrossSourceStatus.Corroborated);
    }

    // Deferred adoptions are documented contracts, not omissions
    [Fact]
    public void Migration_Deferrals_Documented()
    {
        JoinKeyNormalization.ResolveGroupKey(null, null).Should().Be("FILE|unknown");
        // EvidenceId adoption -> H-08.9 (content hash model)
        // hierarchical FILE|path|L<line> -> H-12 (KBF-14-001 audit mapping)
        // path case-folding -> H-07.6 (repository-root normalization)
    }
}