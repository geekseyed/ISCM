using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.8: Common Result Contract (audit X-014: public methods mix
/// null / empty / throw semantics; X-002: analyzer failure was
/// misread as absence of evidence).
///
/// ONE result shape for every Bug Finder service boundary:
///   Success      - payload present (H-01.8.1)
///   Partial      - payload present + diagnostics about gaps (H-01.8.5)
///   Failure      - the INVESTIGATION legitimately concluded a domain
///                  failure (H-01.8.2; reasons mandatory)
///   Unavailable  - the source could not be reached/collected (H-01.8.3)
///   Corrupt      - the source was reached but unreadable (H-01.8.4;
///                  reason mandatory - anti KBF-11-004)
///   DiagnosticError - a BUG IN THE ENGINE ITSELF (H-01.8.6) - never
///                  interchangeable with domain Failure (anti X-002)
///
/// LINKED CONTRACTS:
///   - State aligns with EvidenceState (H-01.4): one vocabulary.
///   - No exceptions for normal flow: factories validate; exceptions
///     are reserved for programmer errors (null factories args).
///   - Diagnostics carry messages + optional exception type name
///     (type names, not exception objects - results stay serializable).
///
/// ADOPTION: no existing service changes in this sub-phase; new and
/// migrated services adopt from H-03 onward.
/// </summary>
public enum ServiceResultKind
{
    Success,
    Partial,
    Failure,
    Unavailable,
    Corrupt,
    DiagnosticError
}

/// <summary>Structured diagnostic entry (serializable; no live exceptions).</summary>
public sealed class ServiceDiagnostic
{
    public string Message { get; init; } = string.Empty;
    public string? ExceptionTypeName { get; init; }
    public string? Source { get; init; }

    public static ServiceDiagnostic From(string message, string? source = null) => new()
    {
        Message = message ?? string.Empty,
        Source = source
    };

    public static ServiceDiagnostic FromException(Exception exception, string? source = null) => new()
    {
        Message = exception.Message,
        ExceptionTypeName = exception.GetType().FullName,
        Source = source
    };
}

/// <summary>
/// The common result contract. T is the payload type; for evidence-free
/// outcomes use ServiceResult&lt;Nothing&gt; (or a unit type) via the
/// non-generic helpers.
/// </summary>
public sealed class ServiceResult<T>
{
    private readonly T? _value;

    public ServiceResultKind Kind { get; }
    public EvidenceState State { get; }

    /// <summary>Payload - meaningful only for Success/Partial.</summary>
    public T? Value => _value;

    public IReadOnlyList<string> Reasons { get; }
    public IReadOnlyList<ServiceDiagnostic> Diagnostics { get; }

    private ServiceResult(
        ServiceResultKind kind, EvidenceState state,
        T? value, IReadOnlyList<string> reasons, IReadOnlyList<ServiceDiagnostic> diagnostics)
        => (Kind, State, _value, Reasons, Diagnostics) = (kind, state, value, reasons, diagnostics);

    // ---------- factories (H-01.8.1-1.8.6) ----------

    public static ServiceResult<T> Success(T value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        return new ServiceResult<T>(
            ServiceResultKind.Success, EvidenceState.Observed, value,
            Array.Empty<string>(), Array.Empty<ServiceDiagnostic>());
    }

    /// <summary>Payload present, but the caller should see the gaps.</summary>
    public static ServiceResult<T> Partial(T value, IReadOnlyList<string> reasons)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        if (reasons is null || reasons.Count == 0)
            throw new ArgumentException("Partial requires at least one reason.", nameof(reasons));
        return new ServiceResult<T>(
            ServiceResultKind.Partial, EvidenceState.Observed, value,
            reasons, Array.Empty<ServiceDiagnostic>());
    }

    /// <summary>The investigation legitimately concluded a domain failure.</summary>
    public static ServiceResult<T> Failure(params string[] reasons)
    {
        if (reasons is null || reasons.Length == 0)
            throw new ArgumentException("Failure requires at least one reason.", nameof(reasons));
        return new ServiceResult<T>(
            ServiceResultKind.Failure, EvidenceState.Observed, default,
            reasons, Array.Empty<ServiceDiagnostic>());
    }

    /// <summary>The source could not be reached or collected (H-01.8.3).</summary>
    public static ServiceResult<T> Unavailable(string reason, string? source = null)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Unavailable requires a reason.", nameof(reason));
        return new ServiceResult<T>(
            ServiceResultKind.Unavailable, EvidenceState.Unavailable, default,
            new[] { reason },
            source is null ? Array.Empty<ServiceDiagnostic>() : new[] { ServiceDiagnostic.From(reason, source) });
    }

    /// <summary>The source was reached but unreadable (H-01.8.4, anti-KBF-11-004).</summary>
    public static ServiceResult<T> Corrupt(string reason, string? source = null)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Corrupt requires a reason.", nameof(reason));
        return new ServiceResult<T>(
            ServiceResultKind.Corrupt, EvidenceState.Corrupt, default,
            new[] { reason },
            source is null ? Array.Empty<ServiceDiagnostic>() : new[] { ServiceDiagnostic.From(reason, source) });
    }

    /// <summary>A bug in the engine itself (H-01.8.6) - never a domain Failure.</summary>
    public static ServiceResult<T> DiagnosticError(Exception exception, string? source = null)
    {
        if (exception is null) throw new ArgumentNullException(nameof(exception));
        return new ServiceResult<T>(
            ServiceResultKind.DiagnosticError, EvidenceState.Unknown, default,
            new[] { $"engine diagnostic error: {exception.Message}" },
            new[] { ServiceDiagnostic.FromException(exception, source) });
    }

    /// <summary>DiagnosticError from an already-captured message.</summary>
    public static ServiceResult<T> DiagnosticError(string message, string? source = null)
    {
        if (string.IsNullOrWhiteSpace(message))
            throw new ArgumentException("DiagnosticError requires a message.", nameof(message));
        return new ServiceResult<T>(
            ServiceResultKind.DiagnosticError, EvidenceState.Unknown, default,
            new[] { $"engine diagnostic error: {message}" },
            new[] { ServiceDiagnostic.From(message, source) });
    }

    // ---------- semantics (H-01.8.7) ----------

    /// <summary>True only for Success/Partial - the payload-bearing kinds.</summary>
    [MemberNotNullWhen(true, nameof(Value))]
    public bool HasValue => Kind is ServiceResultKind.Success or ServiceResultKind.Partial;

    public bool TryGetValue([NotNullWhen(true)] out T? value)
    {
        value = HasValue ? _value : default;
        return HasValue;
    }

    /// <summary>EXPLICIT fallback (H-01.4 Measured pattern) - the caller sees the default.</summary>
    public T ValueOr(T fallback) => HasValue ? _value! : fallback;

    public override string ToString() =>
        $"{Kind}({State}){(HasValue ? " [payload]" : string.Empty)}" +
        (Reasons.Count > 0 ? $" reasons={string.Join("; ", Reasons)}" : string.Empty);
}

/// <summary>Non-generic helpers for evidence-free results (unit payload).</summary>
public static class ServiceResult
{
    /// <summary>Canonical empty payload for evidence-free results.</summary>
    public sealed class Nothing
    {
        public static readonly Nothing Instance = new();
        private Nothing() { }
    }

    public static ServiceResult<Nothing> Success() =>
        ServiceResult<Nothing>.Success(Nothing.Instance);

    public static ServiceResult<Nothing> Partial(IReadOnlyList<string> reasons) =>
        ServiceResult<Nothing>.Partial(Nothing.Instance, reasons);

    public static ServiceResult<Nothing> Failure(params string[] reasons) =>
        ServiceResult<Nothing>.Failure(reasons);

    public static ServiceResult<Nothing> Unavailable(string reason, string? source = null) =>
        ServiceResult<Nothing>.Unavailable(reason, source);

    public static ServiceResult<Nothing> Corrupt(string reason, string? source = null) =>
        ServiceResult<Nothing>.Corrupt(reason, source);

    public static ServiceResult<Nothing> DiagnosticError(Exception exception, string? source = null) =>
        ServiceResult<Nothing>.DiagnosticError(exception, source);
}