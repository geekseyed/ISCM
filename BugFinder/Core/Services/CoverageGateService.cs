using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.8: Coverage Gate Service (audit KBF-06-010 fix).
/// Evaluates the FULL coverage chain evidence (H-04.1 .. H-04.7) and
/// produces one deterministic verdict. PASS requires POSITIVE evidence of
/// every link — Unknown/Partial/Missing/Unavailable never become PASS.
///
/// Stage 4.8.1  real artifact exists: collection evidence (H-04.1) with
///              Status=Collected AND the parsed document (H-04.2) Parsed
///              AND run-to-artifact path BINDING (current run -> current
///              artifact — the exact evidence the audit lacked).
/// Stage 4.8.2  test-to-code mapping: mapping report (H-04.3) present
///              with at least one mapped test; unmapped/missing counts
///              recorded as diagnostics (v1 positional attribution is a
///              documented caveat, never overclaimed).
/// Stage 4.8.3  pass/fail spectrum: TRX ingested (H-03.5), ZERO unknown
///              outcomes (partially classified spectrum is not PASS),
///              non-empty element counters (BF-12 needs rankable data).
/// Stage 4.8.4  domain mapping: OPTIONAL signal. Supplied-but-not-
///              ingested domain source BLOCKS (invalid input must not
///              silently become "no signal"); Unresolved/Ambiguous are
///              honest states — recorded, NEVER inferred as NotCovered
///              (KBF-06-006/007/008 continuity).
/// Stage 4.8.5  provenance: recorded (H-04.7) with test-set identity and
///              mapping completeness. CollectorVersion=Unknown is an
///              honest state accepted by policy — preserved verbatim.
/// Stage 4.8.6  IsBf12Enabled ONLY for Pass; EnsureBf12Authorized is the
///              enforcement API (BF-12 cannot bypass a failed gate).
///
/// VERDICT RULES: not-supplied evidence => Blocked; supplied-but-invalid
/// evidence => Fail; any Fail outweighs Blocked. Deterministic: reason
/// order = stage evaluation order; no clock, no Guid (X-003).
/// The gate authorizes INPUT VALIDITY only — it never emits Root Cause
/// or Fix claims (Strict No-Repair Enforcement, H-01.5.4).
/// </summary>
public class CoverageGateService
{
    public CoverageGateReport Evaluate(CoverageGateInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        var blockers = new List<CoverageGateBlockReason>();
        var diagnostics = new List<string>();
        var stages = new List<CoverageGateStageResult>();

        // ---------- Stage 4.8.1 — Real artifact exists ----------
        var stage481 = true;
        var detail481 = "collection evidence + parsed artifact + run-to-artifact binding verified";

        if (input.Collection is null)
        {
            blockers.Add(CoverageGateBlockReason.CollectionEvidenceMissing);
            stage481 = false;
            detail481 = "H-04.1 collection evidence not supplied — real collection unprovable";
        }
        else if (input.Collection.Status != CoverageCollectionStatus.Collected)
        {
            blockers.Add(CoverageGateBlockReason.CollectionNotCollected);
            stage481 = false;
            detail481 = $"collection status={input.Collection.Status} — no artifact bound to a run";
        }

        if (input.Document is null)
        {
            blockers.Add(CoverageGateBlockReason.CoverageArtifactMissing);
            stage481 = false;
            detail481 = "parsed coverage document not supplied";
        }
        else
        {
            switch (input.Document.Status)
            {
                case CoverageParsingStatus.Parsed:
                    break;
                case CoverageParsingStatus.FileMissing:
                    blockers.Add(CoverageGateBlockReason.CoverageArtifactMissing);
                    stage481 = false;
                    detail481 = $"artifact not found on disk: '{input.Document.SourceArtifactPath}'";
                    break;
                case CoverageParsingStatus.Corrupt:
                    blockers.Add(CoverageGateBlockReason.CoverageArtifactCorrupt);
                    stage481 = false;
                    detail481 = $"artifact corrupt: {input.Document.Reason}";
                    break;
                case CoverageParsingStatus.UnsupportedFormat:
                    blockers.Add(CoverageGateBlockReason.CoverageArtifactUnsupportedFormat);
                    stage481 = false;
                    detail481 = $"unsupported format: {input.Document.Reason}";
                    break;
                case CoverageParsingStatus.NoModules:
                    blockers.Add(CoverageGateBlockReason.CoverageArtifactNoModules);
                    stage481 = false;
                    detail481 = "artifact parsed but contains zero modules";
                    break;
            }

            // Run-to-artifact BINDING — the current run produced THIS artifact
            if (input.Collection is not null && input.Document.Status == CoverageParsingStatus.Parsed)
            {
                try
                {
                    var collected = input.Collection.ArtifactPath;
                    var parsed = input.Document.SourceArtifactPath;
                    var unbound = string.IsNullOrWhiteSpace(collected)
                        || string.IsNullOrWhiteSpace(parsed)
                        || !Path.GetFullPath(collected).Equals(
                               Path.GetFullPath(parsed), StringComparison.Ordinal);

                    if (unbound)
                    {
                        blockers.Add(CoverageGateBlockReason.ArtifactPathUnbound);
                        stage481 = false;
                        detail481 = "collection artifact path != parsed artifact path — " +
                                    "run-to-artifact binding broken";
                    }
                    else
                    {
                        diagnostics.Add(
                            "artifact bound to collection run: " +
                            $"'{Path.GetFullPath(parsed!)}'");
                    }
                }
                catch (Exception ex) when (ex is ArgumentException
                                                or NotSupportedException
                                                or IOException)
                {
                    blockers.Add(CoverageGateBlockReason.ArtifactPathUnbound);
                    stage481 = false;
                    detail481 = $"artifact path binding could not be verified: {ex.Message}";
                }
            }
        }

        stages.Add(new CoverageGateStageResult
        {
            Stage = CoverageGateStage.RealArtifactExists,
            Passed = stage481,
            Detail = detail481
        });

        // ---------- Stage 4.8.2 — Test-to-code mapping ----------
        var stage482 = true;
        if (input.Mapping is null)
        {
            blockers.Add(CoverageGateBlockReason.TestToCodeMappingUnavailable);
            stage482 = false;
        }
        else if (input.Mapping.MappedCount == 0)
        {
            blockers.Add(CoverageGateBlockReason.TestToCodeMappingIncomplete);
            stage482 = false;
        }
        else
        {
            diagnostics.Add(
                $"mapping completeness: mapped={input.Mapping.MappedCount} " +
                $"unmappedDocuments={input.Mapping.UnmappedDocumentCount} " +
                $"missingCoverage={input.Mapping.MissingCoverageCount} " +
                $"distinctElements={input.Mapping.TotalDistinctElements}");
            if (input.Mapping.UnmappedDocumentCount > 0 || input.Mapping.MissingCoverageCount > 0)
                diagnostics.Add(
                    "v1 positional attribution caveat: unmapped documents / missing " +
                    "coverage exist — recorded honestly, never overclaimed as complete");
        }

        stages.Add(new CoverageGateStageResult
        {
            Stage = CoverageGateStage.TestToCodeMapping,
            Passed = stage482,
            Detail = stage482
                ? $"mapping verified: {input.Mapping!.MappedCount} mapped test(s)"
                : "mapping unavailable or incomplete"
        });

        // ---------- Stage 4.8.3 — Pass/Fail spectrum ----------
        var stage483 = true;
        if (input.Spectrum is null)
        {
            blockers.Add(CoverageGateBlockReason.PassFailSpectrumUnavailable);
            stage483 = false;
        }
        else if (input.Spectrum.SourceStatus != TrxIngestionStatus.Ingested)
        {
            blockers.Add(CoverageGateBlockReason.TestSourceNotIngested);
            stage483 = false;
        }
        else if (input.Spectrum.UnknownTestCount > 0)
        {
            blockers.Add(CoverageGateBlockReason.UnclassifiedTestOutcomes);
            stage483 = false;
        }
        else if (input.Spectrum.Elements.Count == 0)
        {
            blockers.Add(CoverageGateBlockReason.ElementSpectrumEmpty);
            stage483 = false;
        }
        else
        {
            diagnostics.Add(
                $"spectrum: passed={input.Spectrum.PassedTestCount} " +
                $"failed={input.Spectrum.FailedTestCount} error={input.Spectrum.ErrorTestCount} " +
                $"skipped={input.Spectrum.SkippedTestCount} " +
                $"unavailable={input.Spectrum.UnavailableTestCount} " +
                $"elements={input.Spectrum.Elements.Count} " +
                "(spectrum is observation only — never a root-cause claim)");
        }

        stages.Add(new CoverageGateStageResult
        {
            Stage = CoverageGateStage.PassFailSpectrum,
            Passed = stage483,
            Detail = stage483
                ? $"spectrum verified over {input.Spectrum!.Elements.Count} element(s)"
                : "spectrum unavailable, unclassified, or empty"
        });

        // ---------- Stage 4.8.4 — Domain mapping ----------
        var stage484 = true;
        var detail484 = "domain correlation not supplied — BF-12 runs on the test " +
                        "spectrum only (honest absence, not a fabricated domain signal)";
        if (input.Domain is not null)
        {
            if (input.Domain.SourceStatus != DomainResultIngestionStatus.Ingested)
            {
                blockers.Add(CoverageGateBlockReason.DomainSourceNotIngested);
                stage484 = false;
                detail484 = $"domain source not ingested: {input.Domain.SourceStatus} — " +
                            "invalid input must not silently become 'no domain signal'";
            }
            else
            {
                detail484 = $"domain mapping: correlated={input.Domain.CorrelatedCount} " +
                            $"ambiguous={input.Domain.AmbiguousCount} " +
                            $"unresolved={input.Domain.UnresolvedCount}";
                diagnostics.Add(detail484 +
                    " (honest states — unresolved mapping is NEVER inferred as NotCovered, " +
                    "KBF-06-006/007/008 continuity)");
            }
        }

        stages.Add(new CoverageGateStageResult
        {
            Stage = CoverageGateStage.DomainMapping,
            Passed = stage484,
            Detail = detail484
        });

        // ---------- Stage 4.8.5 — Provenance ----------
        var stage485 = true;
        if (input.Provenance is null)
        {
            blockers.Add(CoverageGateBlockReason.ProvenanceUnavailable);
            stage485 = false;
        }
        else if (input.Provenance.Status != CoverageProvenanceStatus.Recorded)
        {
            blockers.Add(CoverageGateBlockReason.ProvenanceNotRecorded);
            stage485 = false;
        }
        else if (!input.Provenance.HasTestSet || !input.Provenance.HasMappingCompleteness)
        {
            blockers.Add(CoverageGateBlockReason.ProvenanceIncomplete);
            stage485 = false;
        }
        else
        {
            if (input.Provenance.CollectorVersion is null)
                diagnostics.Add(
                    "provenance: collector version Unknown (honest state — preserved " +
                    "verbatim, accepted by documented policy)");
            diagnostics.Add(
                "provenance: evidenceId=" +
                $"{input.Provenance.EvidenceId?.Value ?? "Unknown"} " +
                $"session={(input.Provenance.SessionId?.Value ?? "Unknown")} " +
                $"artifactSha256={Truncate(input.Provenance.ArtifactSha256, 12)}…");
        }

        stages.Add(new CoverageGateStageResult
        {
            Stage = CoverageGateStage.Provenance,
            Passed = stage485,
            Detail = stage485 ? "provenance recorded and complete (per policy)" : "provenance unavailable or incomplete"
        });

        // ---------- Verdict (4.8.6) ----------
        var verdict = blockers.Count == 0
            ? CoverageGateVerdict.Pass
            : blockers.Any(IsInvalidEvidence)
                ? CoverageGateVerdict.Fail
                : CoverageGateVerdict.Blocked;

        return new CoverageGateReport
        {
            Verdict = verdict,
            BlockReasons = blockers,          // stage evaluation order — deterministic
            Stages = stages,
            Diagnostics = diagnostics
        };
    }

    /// <summary>
    /// Supplied-but-invalid reasons (=> Fail). Everything else
    /// (evidence NOT SUPPLIED) is Blocked-type.
    /// </summary>
    private static bool IsInvalidEvidence(CoverageGateBlockReason reason) =>
        reason is not (CoverageGateBlockReason.CollectionEvidenceMissing
            or CoverageGateBlockReason.CoverageArtifactMissing
            or CoverageGateBlockReason.TestToCodeMappingUnavailable
            or CoverageGateBlockReason.PassFailSpectrumUnavailable
            or CoverageGateBlockReason.ProvenanceUnavailable);

    private static string Truncate(string value, int length) =>
        value.Length <= length ? value : value[..length];
}