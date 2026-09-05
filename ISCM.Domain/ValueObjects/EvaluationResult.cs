using ISCM.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace ISCM.Domain.ValueObjects;

/// <summary>
/// Immutable value object representing the result of a typed evidence evaluation.
///
/// This is the canonical output of ITypedEvidenceEvaluator and ITypeSpecificEvaluator.
/// It carries:
///   - Status (Pass / Fail / Error / Unknown / NotApplicable)
///   - Reason (human-readable explanation)
///   - Details (structured metadata: actual, expected, operator, valueType, unit, path)
///   - EvaluatedAtUtc (timestamp for audit)
///
/// Factory methods enforce valid state transitions.
/// Direct constructor is private to prevent malformed instances.
///
/// Phase 7 — Typed Evaluation
/// </summary>
public sealed class EvaluationResult
{
    public CheckStatus Status { get; }
    public string Reason { get; }
    public IReadOnlyDictionary<string, string> Details { get; }
    public DateTime EvaluatedAtUtc { get; }

    private EvaluationResult(
        CheckStatus status,
        string reason,
        IDictionary<string, string>? details)
    {
        Status = status;
        Reason = reason ?? string.Empty;
        Details = details != null
            ? new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(details))
            : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());
        EvaluatedAtUtc = DateTime.UtcNow;
    }

    // ----- Derived properties -----

    public bool IsPass => Status == CheckStatus.Pass;
    public bool IsFail => Status == CheckStatus.Fail;
    public bool IsError => Status == CheckStatus.Error;
    public bool IsUnknown => Status == CheckStatus.Unknown;
    public bool IsNotApplicable => Status == CheckStatus.NotApplicable;

    // ----- Factory methods -----

    public static EvaluationResult Pass(string reason, IDictionary<string, string>? details = null)
        => new(CheckStatus.Pass, reason, details);

    public static EvaluationResult Fail(string reason, IDictionary<string, string>? details = null)
        => new(CheckStatus.Fail, reason, details);

    public static EvaluationResult Error(string reason, IDictionary<string, string>? details = null)
        => new(CheckStatus.Error, reason, details);

    public static EvaluationResult Unknown(string reason, IDictionary<string, string>? details = null)
        => new(CheckStatus.Unknown, reason, details);

    public static EvaluationResult NotApplicable(string reason, IDictionary<string, string>? details = null)
        => new(CheckStatus.NotApplicable, reason, details);

    /// <summary>
    /// Helper to build the standard detail dictionary used by typed comparers.
    /// Ensures consistent keys across all evaluators for audit/UI consumption.
    /// </summary>
    public static Dictionary<string, string> BuildDetails(
        string? actual,
        string? expected,
        Operator op,
        string? valueType,
        string? unit = null,
        string? path = null,
        string? extra = null)
    {
        var details = new Dictionary<string, string>
        {
            ["actual"] = actual ?? "(null)",
            ["expected"] = expected ?? "(null)",
            ["operator"] = op.ToString(),
            ["valueType"] = valueType ?? "Unknown"
        };

        if (!string.IsNullOrWhiteSpace(unit))
            details["unit"] = unit;

        if (!string.IsNullOrWhiteSpace(path))
            details["path"] = path;

        if (!string.IsNullOrWhiteSpace(extra))
            details["extra"] = extra;

        return details;
    }

    /// <summary>
    /// Converts the result back to a legacy (CheckStatus, string) tuple
    /// for migration period where some call sites still expect tuples.
    /// </summary>
    public (CheckStatus Status, string Reason) ToLegacyTuple()
        => (Status, Reason);

    public override string ToString()
        => $"[{Status}] {Reason}";
}