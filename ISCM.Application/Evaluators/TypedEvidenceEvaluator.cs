using ISCM.Application.Interfaces;
using ISCM.Application.Services;
using ISCM.Application.Evaluators.Typed;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;

namespace ISCM.Application.Evaluators;

/// <summary>
/// Main typed evidence evaluator — implements ITypedEvidenceEvaluator.
/// 
/// This is the public entry point for typed evaluation in Phase 7.
/// It receives typed EvidenceValue (from Normalization layer, Phase 6) and
/// catalog-declared expected value, then routes to the appropriate type-specific evaluator.
/// 
/// Flow:
///   1. Validate actual EvidenceValue and TypedValue are non-null
///   2. Parse expectedValueString via ExpectedValueParser into typed object
///   3. Dispatch by EvidenceValueType (not CLR type) to correct ITypeSpecificEvaluator
///   4. Return EvaluationResult (Pass / Fail / Error)
/// 
/// Design rules:
///   - NEVER falls back to legacy IEvidenceEvaluator silently.
///   - If TypedValue is null (normalization failed), returns Error.
///   - If expected string cannot be parsed, returns Error.
///   - If actual type does not match expected type, returns Error (type mismatch).
///   - Routing is based on EvidenceValueType (from catalog), not CLR type.
///     This is essential because Long/Size share CLR type 'long',
///     and Enum/RegistryValue/PolicyValue share CLR type 'object'.
/// 
/// Phase 7 — Typed Evaluation, Sub-Phase 7.4
/// </summary>
public sealed class TypedEvidenceEvaluator : ITypedEvidenceEvaluator
{
    private readonly ExpectedValueParser _parser;
    private readonly IntegerEvaluator _intEval;
    private readonly LongEvaluator _longEval;
    private readonly BooleanEvaluator _boolEval;
    private readonly StringEvaluator _strEval;
    private readonly DurationEvaluator _durEval;
    private readonly SizeEvaluator _sizeEval;
    private readonly EnumEvaluator _enumEval;
    private readonly CollectionEvaluator _collEval;
    private readonly RegistryValueEvaluator _regEval;
    private readonly PolicyValueEvaluator _policyEval;

    public TypedEvidenceEvaluator(
        ExpectedValueParser parser,
        IntegerEvaluator intEval,
        LongEvaluator longEval,
        BooleanEvaluator boolEval,
        StringEvaluator strEval,
        DurationEvaluator durEval,
        SizeEvaluator sizeEval,
        EnumEvaluator enumEval,
        CollectionEvaluator collEval,
        RegistryValueEvaluator regEval,
        PolicyValueEvaluator policyEval)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _intEval = intEval ?? throw new ArgumentNullException(nameof(intEval));
        _longEval = longEval ?? throw new ArgumentNullException(nameof(longEval));
        _boolEval = boolEval ?? throw new ArgumentNullException(nameof(boolEval));
        _strEval = strEval ?? throw new ArgumentNullException(nameof(strEval));
        _durEval = durEval ?? throw new ArgumentNullException(nameof(durEval));
        _sizeEval = sizeEval ?? throw new ArgumentNullException(nameof(sizeEval));
        _enumEval = enumEval ?? throw new ArgumentNullException(nameof(enumEval));
        _collEval = collEval ?? throw new ArgumentNullException(nameof(collEval));
        _regEval = regEval ?? throw new ArgumentNullException(nameof(regEval));
        _policyEval = policyEval ?? throw new ArgumentNullException(nameof(policyEval));
    }

    // =========================================================================
    // ITypedEvidenceEvaluator: value-based overload (preferred)
    // =========================================================================

    public EvaluationResult Evaluate(
        EvidenceValue actualValue,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op)
    {
        // 1. Validate actual value
        if (actualValue == null)
        {
            return EvaluationResult.Error(
                "EvidenceValue is null. Cannot evaluate.",
                EvaluationResult.BuildDetails(
                    actual: "(null)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString()));
        }

        if (actualValue.TypedValue == null)
        {
            // Normalization failed or was not performed — explicit Error, not silent fallback
            return EvaluationResult.Error(
                "EvidenceValue.TypedValue is null. Normalization layer did not produce a typed value. " +
                "This indicates a parser/normalizer failure that must be fixed, not silently worked around.",
                EvaluationResult.BuildDetails(
                    actual: actualValue.RawString ?? "(null raw)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString(),
                    extra: $"ValueType={actualValue.ValueType}"));
        }

        // 2. Parse expected value
        var parseResult = _parser.Parse(expectedValueString, expectedType);

        // For Size/Long, use specialized parsers that return typed ParseResult<T>
        if (expectedType == ExpectedValueType.Collection && !parseResult.IsSuccess)
        {
            return EvaluationResult.Error(
                $"Cannot parse expected Collection value: {parseResult.Error}",
                EvaluationResult.BuildDetails(
                    actual: actualValue.TypedValue?.ToString() ?? "(null)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString()));
        }

        if (!parseResult.IsSuccess)
        {
            return EvaluationResult.Error(
                $"Cannot parse expected value '{expectedValueString}' as {expectedType}: {parseResult.Error}",
                EvaluationResult.BuildDetails(
                    actual: actualValue.TypedValue?.ToString() ?? "(null)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString()));
        }

        var expectedTyped = parseResult.Value;

        // 3. Dispatch by EvidenceValueType
        return Dispatch(expectedType, actualValue.TypedValue, expectedTyped, op, expectedValueString);
    }

    // =========================================================================
    // ITypedEvidenceEvaluator: entity-based overload (migration convenience)
    // =========================================================================

    // =========================================================================
    // ITypedEvidenceEvaluator: entity-based overload (migration convenience)
    // =========================================================================

    public EvaluationResult Evaluate(
        Evidence evidence,
        string expectedValueString,
        ExpectedValueType expectedType,
        Operator op)
    {
        if (evidence == null)
        {
            return EvaluationResult.Error(
                "Evidence entity is null. Cannot evaluate.",
                EvaluationResult.BuildDetails(
                    actual: "(null)",
                    expected: expectedValueString,
                    op: op,
                    valueType: expectedType.ToString()));
        }

        // Use evidence.TypedValue directly if normalization has already produced one.
        // Otherwise, synthesize a minimal EvidenceValue from the raw Evidence fields
        // (this path exists only for backward compatibility during migration).
        EvidenceValue evidenceValue = evidence.TypedValue
            ?? new EvidenceValue(
                value: null,
                type: evidence.ValueType,
                unit: null,
                rawString: evidence.ParsedValue ?? evidence.RawOutput ?? string.Empty);

        return Evaluate(evidenceValue, expectedValueString, expectedType, op);
    }

    // =========================================================================
    // Dispatch by EvidenceValueType
    // =========================================================================

    private EvaluationResult Dispatch(
        ExpectedValueType expectedType,
        object actualTyped,
        object expectedTyped,
        Operator op,
        string expectedString)
    {
        return expectedType switch
        {
            ExpectedValueType.Integer => DispatchInteger(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.Boolean => DispatchBoolean(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.Duration => DispatchDuration(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.String => DispatchString(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.Enum => DispatchEnum(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.RegistryValue => DispatchRegistryValue(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.PolicyValue => DispatchPolicyValue(actualTyped, expectedTyped, op, expectedString),
            ExpectedValueType.Collection => DispatchCollection(actualTyped, expectedTyped, op, expectedString),

            _ => EvaluationResult.Error(
                $"Unsupported ExpectedValueType: {expectedType}.",
                EvaluationResult.BuildDetails(
                    actual: actualTyped?.ToString() ?? "(null)",
                    expected: expectedString,
                    op: op,
                    valueType: expectedType.ToString()))
        };
    }

    private EvaluationResult DispatchInteger(
        object actual, object expected, Operator op, string expectedString)
    {
        if (actual is int actualInt && expected is int expectedInt)
        {
            return _intEval.Compare(actualInt, expectedInt, op);
        }

        return EvaluationResult.Error(
            $"Integer evaluation requires int values. Got actual={actual?.GetType().Name ?? "null"}, " +
            $"expected={expected?.GetType().Name ?? "null"}. This is a type mismatch between " +
            $"normalizer output and catalog declaration.",
            EvaluationResult.BuildDetails(
                actual: actual?.ToString() ?? "(null)",
                expected: expectedString,
                op: op,
                valueType: "Integer"));
    }

    private EvaluationResult DispatchBoolean(
        object actual, object expected, Operator op, string expectedString)
    {
        if (actual is bool actualBool && expected is bool expectedBool)
        {
            return _boolEval.Compare(actualBool, expectedBool, op);
        }

        return EvaluationResult.Error(
            $"Boolean evaluation requires bool values. Got actual={actual?.GetType().Name ?? "null"}, " +
            $"expected={expected?.GetType().Name ?? "null"}.",
            EvaluationResult.BuildDetails(
                actual: actual?.ToString() ?? "(null)",
                expected: expectedString,
                op: op,
                valueType: "Boolean"));
    }

    private EvaluationResult DispatchDuration(
        object actual, object expected, Operator op, string expectedString)
    {
        if (actual is TimeSpan actualTs && expected is TimeSpan expectedTs)
        {
            return _durEval.Compare(actualTs, expectedTs, op);
        }

        return EvaluationResult.Error(
            $"Duration evaluation requires TimeSpan values. Got actual={actual?.GetType().Name ?? "null"}, " +
            $"expected={expected?.GetType().Name ?? "null"}.",
            EvaluationResult.BuildDetails(
                actual: actual?.ToString() ?? "(null)",
                expected: expectedString,
                op: op,
                valueType: "Duration"));
    }

    private EvaluationResult DispatchString(
        object actual, object expected, Operator op, string expectedString)
    {
        var actualStr = actual as string ?? actual?.ToString() ?? string.Empty;
        var expectedStr = expected as string ?? expected?.ToString() ?? string.Empty;

        return _strEval.Compare(actualStr, expectedStr, op);
    }

    private EvaluationResult DispatchEnum(
        object actual, object expected, Operator op, string expectedString)
    {
        return _enumEval.Compare(actual, expected, op);
    }

    private EvaluationResult DispatchRegistryValue(
        object actual, object expected, Operator op, string expectedString)
    {
        return _regEval.Compare(actual, expected, op);
    }

    private EvaluationResult DispatchPolicyValue(
        object actual, object expected, Operator op, string expectedString)
    {
        return _policyEval.Compare(actual, expected, op);
    }

    private EvaluationResult DispatchCollection(
        object actual, object expected, Operator op, string expectedString)
    {
        if (actual is IReadOnlyCollection<object> actualColl && expected is IReadOnlyCollection<object> expectedColl)
        {
            return _collEval.Compare(actualColl, expectedColl, op);
        }

        return EvaluationResult.Error(
            $"Collection evaluation requires IReadOnlyCollection<object> values. " +
            $"Got actual={actual?.GetType().Name ?? "null"}, expected={expected?.GetType().Name ?? "null"}.",
            EvaluationResult.BuildDetails(
                actual: actual?.ToString() ?? "(null)",
                expected: expectedString,
                op: op,
                valueType: "Collection"));
    }
}