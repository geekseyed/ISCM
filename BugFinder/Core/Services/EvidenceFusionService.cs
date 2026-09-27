using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// BF-14.1: Evidence Fusion Service
/// Stage 1 Collect + Stage 2 Normalize → Normalize()
/// Stage 3 Weight + Stage 4 Fuse + Stage 5 Package → Fuse()
/// Adapters: FromRankedResult (BF-12.10), FromCorrelationReport (BF-13.8).
/// H-01.7: group keys resolve through the typed join-key normalization
/// layer (JoinKeyNormalization) so Fusion, Consistency and Conflict
/// agree on group membership for padded and separator-variant keys,
/// and the report carries typed-join diagnostics (case-variant keys,
/// untargeted evidence).
/// Principles: no fabrication (evidence-less candidates contribute nothing);
/// uncorrelated items skipped (UNKNOWN), never treated as failure.
/// </summary>
public class EvidenceFusionService
{
    private readonly EvidenceWeightConfig _config;

    public EvidenceFusionService(EvidenceWeightConfig? config = null)
    {
        _config = config ?? new EvidenceWeightConfig();
    }

    // Stage 1 + 2 — collect & normalize
    public List<FusionEvidenceInput> Normalize(IEnumerable<FusionEvidenceInput>? inputs)
    {
        if (inputs is null) return new List<FusionEvidenceInput>();

        return inputs.Select(input => new FusionEvidenceInput
        {
            SourceType = input.SourceType,
            RawStrength = Math.Clamp(input.RawStrength, 0.0, 1.0),
            TargetSymbolKey = NullIfEmpty(input.TargetSymbolKey),
            TargetFilePath = NullIfEmpty(input.TargetFilePath),
            TargetLineNumber = input.TargetLineNumber,
            ObservedAtUtc = input.ObservedAtUtc,
            SourceArtifact = NullIfEmpty(input.SourceArtifact),
            Description = NullIfEmpty(input.Description)
        }).ToList();
    }

    // Stage 3 + 4 + 5 — weight, fuse, package
    public EvidenceFusionReport Fuse(IEnumerable<FusionEvidenceInput>? inputs)
    {
        var normalized = Normalize(inputs);
        var report = new EvidenceFusionReport { TotalInputs = normalized.Count };

        foreach (var group in normalized.GroupBy(ResolveGroupKey))
        {
            var items = group.ToList();

            double weightedSum = 0, totalWeight = 0, max = 0;
            foreach (var item in items)
            {
                var weight = _config.GetWeight(item.SourceType);
                weightedSum += weight * item.RawStrength;
                totalWeight += weight;
                if (item.RawStrength > max) max = item.RawStrength;
            }

            var sources = items.Select(i => i.SourceType).Distinct().OrderBy(s => s).ToList();

            report.Items.Add(new FusedEvidenceItem
            {
                TargetKey = group.Key,
                TargetSymbolKey = items[0].TargetSymbolKey,
                TargetFilePath = items.Select(i => i.TargetFilePath).FirstOrDefault(p => p is not null),
                TargetLineNumber = items[0].TargetLineNumber,
                FusedStrength = totalWeight > 0 ? weightedSum / totalWeight : 0.0,
                MaxSingleStrength = max,
                SignalCount = items.Count,
                DistinctSourceCount = sources.Count,
                Sources = sources
            });
        }

        // H-01.7 — typed join index over the resolved group keys: surfaces
        // case-variant and untargeted join hazards without changing grouping.
        var diagnostics = new List<string>(
            TypedJoinIndex.Build(report.Items.Select(i => i.TargetKey)).Diagnostics);
        var untargeted = report.Items.Count(i => i.TargetKey == "FILE|unknown");
        if (untargeted > 0)
            diagnostics.Add($"{untargeted} fused target(s) carry neither a symbol key nor a file path (FILE|unknown)");
        report.JoinDiagnostics = diagnostics;

        return Finalize(report);
    }

    // Adapter — BF-12.10 ranked candidates (evidence-bearing only; no fabrication)
    public List<FusionEvidenceInput> FromRankedResult(RankedLocalizationResult? ranked)
    {
        var inputs = new List<FusionEvidenceInput>();
        if (ranked is null) return inputs;

        foreach (var candidate in ranked.Candidates)
        {
            foreach (var evidence in candidate.Evidence)
            {
                inputs.Add(new FusionEvidenceInput
                {
                    SourceType = evidence.Type,
                    RawStrength = evidence.Strength,
                    TargetFilePath = candidate.FilePath,
                    TargetLineNumber = candidate.LineNumber,
                    SourceArtifact = evidence.SourceArtifact,
                    Description = $"BF-12.10 {candidate.ElementId} (rank {candidate.Rank})"
                });
            }
        }
        return inputs;
    }

    // Adapter — BF-13.8 correlation report (correlated items only)
    public List<FusionEvidenceInput> FromCorrelationReport(StaticDynamicCorrelationReport? correlation)
    {
        var inputs = new List<FusionEvidenceInput>();
        if (correlation is null) return inputs;

        foreach (var item in correlation.Items)
        {
            if (!item.IsCorrelated || item.PrimarySymbolKey is null) continue; // UNKNOWN → skip

            inputs.Add(new FusionEvidenceInput
            {
                SourceType = CandidateEvidenceType.StaticCorrelation,
                RawStrength = Math.Clamp(item.Dynamic.SignalStrength * item.MatchConfidence, 0.0, 1.0),
                TargetSymbolKey = item.PrimarySymbolKey,
                TargetFilePath = item.Dynamic.FilePath,
                TargetLineNumber = item.Dynamic.LineNumber,
                SourceArtifact = item.Dynamic.SourceArtifact,
                Description = $"BF-13.8 {item.Strategy}"
            });
        }
        return inputs;
    }

    // ---------- internals ----------

    private static EvidenceFusionReport Finalize(EvidenceFusionReport report)
    {
        report.Items = report.Items
            .OrderByDescending(i => i.FusedStrength)
            .ThenByDescending(i => i.DistinctSourceCount)
            .ThenBy(i => i.TargetKey)
            .ToList();

        report.TotalTargets = report.Items.Count;
        report.FullyCorroboratedCount = report.Items.Count(i => i.DistinctSourceCount >= 2);
        return report;
    }

    // Symbol key wins; otherwise group by file (evidence without any target
    // still lands in an explicit UNTARGETED group — nothing is dropped).
    // H-01.7.1/1.7.2: resolution goes through the typed normalization layer
    // so Fusion, Consistency and Conflict share ONE group-membership truth
    // (pre-H-01.7 hazard: Fusion normalized while the other two trusted
    // raw strings - the same event could split differently per service).
    public static string ResolveGroupKey(FusionEvidenceInput input) =>
        JoinKeyNormalization.ResolveGroupKey(input.TargetSymbolKey, input.TargetFilePath);

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}