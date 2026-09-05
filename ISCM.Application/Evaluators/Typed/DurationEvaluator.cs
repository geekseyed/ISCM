using ISCM.Application.Evaluators.Comparison;
using ISCM.Application.Interfaces;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators.Typed;

/// <summary>
/// Type-specific evaluator for Duration (TimeSpan) values.
/// 
/// Handles: EvidenceValueType.Duration
/// Supported operators: Equals, NotEquals, GreaterThan, GreaterOrEqual, LessThan, LessOrEqual
/// 
/// Unit-aware: internally all durations are compared as TimeSpan, but reason messages
/// format the duration in the most readable unit (days/hours/minutes/seconds).
/// 
/// Examples from catalog:
///   "60 days"    → TimeSpan.FromDays(60)
///   "15 minutes" → TimeSpan.FromMinutes(15)
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.3
/// </summary>
public sealed class DurationEvaluator : ITypeSpecificEvaluator<TimeSpan>
{
    public string EvaluatorName => "DurationEvaluator";

    public IReadOnlySet<EvidenceValueType> SupportedTypes { get; } =
        new HashSet<EvidenceValueType> { EvidenceValueType.Duration };

    public EvaluationResult Compare(TimeSpan actual, TimeSpan expected, Operator op)
    {
        return TypedComparers.CompareDuration(actual, expected, op);
    }
}