using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Main typed evaluation contract — the public API consumed by the scanner pipeline.
///
/// This interface is the boundary between the Normalization layer (Phase 6) and the
/// Evaluation layer (Phase 7). It receives typed EvidenceValue (output of normalization)
/// and the catalog-declared expected value as a string + declared type + operator.
///
/// Hard rules:
///   1. NEVER receives raw strings for evaluation.
///   2. NEVER silently converts to legacy IEvidenceEvaluator.
///   3. If the actual EvidenceValue.TypedValue is null, returns Error (not Pass, not fallback).
///   4. If the expected value cannot be parsed according to declared expectedType, returns Error.
///   5. If the actual TypedValue type does not match the declared expectedType, returns Error
///      (type mismatch is a contract violation, not a silent conversion opportunity).
///
/// Two overloads are provided:
///   - Value-based: takes EvidenceValue directly (preferred in new code).
///   - Entity-based: takes Evidence entity (convenience for existing scanner call sites).
///
/// Phase 7 — Typed Evaluation
/// </summary>
public interface ITypedEvidenceEvaluator
{
    /// <summary>
    /// Evaluates a typed EvidenceValue against a catalog-declared expected value.
    /// </summary>
    /// <param name="actualValue">
    /// The typed evidence value produced by the Normalization layer (Phase 6).
    /// Must be non-null and must have a non-null TypedValue.
    /// </param>
    /// <param name="expectedValueString">
    /// The expected value as stored in the catalog (e.g., "14 characters", "60 days", "Enabled").
    /// The declared expectedType determines how this string is parsed into a typed form.
    /// </param>
    /// <param name="expectedType">
    /// The declared type from the catalog. Drives typed parsing of expectedValueString.
    /// </param>
    /// <param name="op">
    /// The declared comparison operator from the catalog.
    /// </param>
    /// <returns>
    /// EvaluationResult with Pass, Fail, Error, or Unknown status.
    /// Error is returned when:
    ///   - actualValue is null
    ///   - actualValue.TypedValue is null (normalization failed)
    ///   - expectedValueString cannot be parsed as expectedType
    ///   - actualValue.ValueType is incompatible with expectedType
    ///   - the declared Operator is not supported for the given type
    /// </returns>
    EvaluationResult Evaluate(
        EvidenceValue actualValue,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op);

    /// <summary>
    /// Convenience overload that takes an Evidence entity directly.
    /// Extracts TypedValue, ParsedValue, and other fields internally.
    /// 
    /// This overload exists to minimize changes to existing scanner call sites
    /// during the migration period. New code should prefer the value-based overload.
    /// </summary>
    EvaluationResult Evaluate(
        Evidence evidence,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op);
}