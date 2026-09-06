using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;

namespace ISCM.Domain.Entities;

/// <summary>
/// Represents the result of a single verification path execution.
/// 
/// Phase 8 — Verification Architecture
/// 
/// Contract (from Final Engineering Specification, Section 8.1):
///   PathResult must contain:
///     - PathId
///     - Source
///     - Collector
///     - Parser
///     - Normalizer
///     - Evaluator
///     - Result
///     - EvidenceId
///     - Execution timestamp
/// 
/// Hard rules:
///   1. One PathResult per VerificationPath per scan.
///   2. Each path receives separate evidence (no cross-path contamination).
///   3. PathResult is immutable after construction.
///   4. The path result is preserved even when the agreement engine
///      produces a different SubControl verdict.
/// 
/// Backward compatibility:
///   - The legacy Status (CheckStatus) and EvaluationDetail (string) properties
///     are preserved so existing code continues to work.
///   - The new TypedEvaluation (EvaluationResult from Phase 7) is optional
///     and populated only when typed evaluation is used.
/// </summary>
public class PathResult
{
    // =========================================================================
    // Identity
    // =========================================================================

    /// <summary>
    /// The PathId this result belongs to.
    /// </summary>
    public string PathId { get; set; } = string.Empty;

    /// <summary>
    /// Source name as declared in the VerificationPath.
    /// </summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>
    /// Acquisition mechanism used.
    /// </summary>
    public string AcquisitionMechanism { get; set; } = string.Empty;

    // =========================================================================
    // Pipeline components (for audit / UI traceability)
    // =========================================================================

    /// <summary>
    /// Name of the collector that acquired the raw evidence.
    /// </summary>
    public string CollectorName { get; set; } = string.Empty;

    /// <summary>
    /// Name of the parser that processed the raw output.
    /// </summary>
    public string ParserName { get; set; } = string.Empty;

    /// <summary>
    /// Name of the normalizer that produced the typed value.
    /// </summary>
    public string NormalizerName { get; set; } = string.Empty;

    /// <summary>
    /// Name of the evaluator that produced the verdict.
    /// </summary>
    public string EvaluatorName { get; set; } = string.Empty;

    // =========================================================================
    // Result (legacy — preserved for backward compatibility)
    // =========================================================================

    /// <summary>
    /// Legacy status field. Retained for backward compatibility with
    /// existing scanners that predate Phase 7 typed evaluation.
    /// New code should use TypedEvaluation.Status when available.
    /// </summary>
    public CheckStatus Status { get; set; } = CheckStatus.Unknown;

    /// <summary>
    /// Legacy human-readable evaluation detail.
    /// New code should use TypedEvaluation.Reason when available.
    /// </summary>
    public string EvaluationDetail { get; set; } = string.Empty;

    // =========================================================================
    // Result (Phase 7 typed — preferred)
    // =========================================================================

    /// <summary>
    /// Typed evaluation result from Phase 7 pipeline.
    /// Null when the path used legacy string-based evaluation.
    /// </summary>
    public EvaluationResult? TypedEvaluation { get; set; }

    // =========================================================================
    // Evidence reference
    // =========================================================================

    /// <summary>
    /// The EvidenceId this path produced.
    /// Null if evidence collection failed.
    /// </summary>
    public string? EvidenceId { get; set; }

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /// <summary>
    /// Free-form diagnostic information (errors, warnings, timing).
    /// </summary>
    public string? DiagnosticInfo { get; set; }

    /// <summary>
    /// Duration of path execution in milliseconds.
    /// </summary>
    public int DurationMs { get; set; }

    /// <summary>
    /// Whether the path was skipped (e.g., optional and unavailable).
    /// </summary>
    public bool WasSkipped { get; set; }

    /// <summary>
    /// Reason for skipping (if WasSkipped is true).
    /// </summary>
    public string? SkipReason { get; set; }

    // =========================================================================
    // Timing
    // =========================================================================

    /// <summary>
    /// When this path was executed (UTC).
    /// </summary>
    public DateTime ExecutedAt { get; set; } = DateTime.UtcNow;

    // =========================================================================
    // Constructors
    // =========================================================================

    public PathResult() { }

    public PathResult(
        string pathId,
        string source,
        string acquisitionMechanism,
        CheckStatus status,
        string evaluationDetail,
        string? evidenceId = null,
        string? diagnosticInfo = null)
    {
        PathId = pathId ?? throw new ArgumentNullException(nameof(pathId));
        Source = source ?? string.Empty;
        AcquisitionMechanism = acquisitionMechanism ?? string.Empty;
        Status = status;
        EvaluationDetail = evaluationDetail ?? string.Empty;
        EvidenceId = evidenceId;
        DiagnosticInfo = diagnosticInfo;
        ExecutedAt = DateTime.UtcNow;
    }

    // =========================================================================
    // Factory methods
    // =========================================================================

    /// <summary>
    /// Create a Pass path result.
    /// </summary>
    public static PathResult Pass(
        string pathId, string source, string mechanism,
        string reason, string? evidenceId = null)
        => new(pathId, source, mechanism, CheckStatus.Pass, reason, evidenceId);

    /// <summary>
    /// Create a Fail path result.
    /// </summary>
    public static PathResult Fail(
        string pathId, string source, string mechanism,
        string reason, string? evidenceId = null)
        => new(pathId, source, mechanism, CheckStatus.Fail, reason, evidenceId);

    /// <summary>
    /// Create an Error path result.
    /// </summary>
    public static PathResult Error(
        string pathId, string source, string mechanism,
        string errorReason, string? diagnosticInfo = null)
        => new(pathId, source, mechanism, CheckStatus.Error, errorReason, null, diagnosticInfo);

    /// <summary>
    /// Create an Unknown path result.
    /// </summary>
    public static PathResult Unknown(
        string pathId, string source, string mechanism,
        string reason, string? diagnosticInfo = null)
        => new(pathId, source, mechanism, CheckStatus.Unknown, reason, null, diagnosticInfo);

    /// <summary>
    /// Create a Skipped path result (optional + unavailable).
    /// </summary>
    public static PathResult Skipped(
        string pathId, string source, string mechanism,
        string skipReason)
    {
        var result = new PathResult(pathId, source, mechanism,
            CheckStatus.NotApplicable, $"Skipped: {skipReason}");
        result.WasSkipped = true;
        result.SkipReason = skipReason;
        return result;
    }

    /// <summary>
    /// Create a path result from a Phase 7 EvaluationResult (typed path).
    /// </summary>
    public static PathResult FromTypedEvaluation(
        string pathId,
        string source,
        string mechanism,
        EvaluationResult typedEvaluation,
        string? evidenceId = null,
        string? collectorName = null,
        string? parserName = null,
        string? normalizerName = null,
        string? evaluatorName = null,
        int durationMs = 0)
    {
        if (typedEvaluation == null)
            throw new ArgumentNullException(nameof(typedEvaluation));

        return new PathResult
        {
            PathId = pathId,
            Source = source,
            AcquisitionMechanism = mechanism,
            Status = typedEvaluation.Status,
            EvaluationDetail = typedEvaluation.Reason,
            TypedEvaluation = typedEvaluation,
            EvidenceId = evidenceId,
            CollectorName = collectorName ?? string.Empty,
            ParserName = parserName ?? string.Empty,
            NormalizerName = normalizerName ?? string.Empty,
            EvaluatorName = evaluatorName ?? string.Empty,
            DurationMs = durationMs,
            ExecutedAt = DateTime.UtcNow
        };
    }

    public override string ToString()
        => $"[{Status}] PathId={PathId}, Source={Source}, Detail={EvaluationDetail}";
}