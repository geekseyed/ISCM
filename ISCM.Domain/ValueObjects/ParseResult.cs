namespace ISCM.Domain.ValueObjects;

public enum ParseState
{
    Success = 0,
    Missing = 1,
    Invalid = 2,
    Error = 3
}

/// <summary>
/// Explicit parse result: Raw Input → ParseResult<T>
/// MUST distinguish Success / Missing / Invalid / Error.
/// NEVER fabricate defaults on failure.
/// </summary>
public class ParseResult<T>
{
    public ParseState State { get; }
    public T? Value { get; }
    public ParseError? Error { get; }
    public string? RawInput { get; }
    public DateTime ParsedAtUtc { get; }

    private ParseResult(ParseState state, T? value, ParseError? error, string? rawInput)
    {
        State = state;
        Value = value;
        Error = error;
        RawInput = rawInput;
        ParsedAtUtc = DateTime.UtcNow;
    }

    public bool IsSuccess => State == ParseState.Success;
    public bool IsMissing => State == ParseState.Missing;
    public bool IsInvalid => State == ParseState.Invalid;
    public bool IsError => State == ParseState.Error;
    public bool IsFailure => !IsSuccess;

    // === FACTORY METHODS ===

    public static ParseResult<T> Success(T value, string? rawInput = null)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));
        return new ParseResult<T>(ParseState.Success, value, null, rawInput);
    }

    public static ParseResult<T> Missing(string reason, string? rawInput = null)
    {
        return new ParseResult<T>(ParseState.Missing, default,
            ParseError.Create(ParseErrorCode.KeyNotFound, reason), rawInput);
    }

    public static ParseResult<T> Invalid(string reason, string? rawInput = null)
    {
        return new ParseResult<T>(ParseState.Invalid, default,
            ParseError.Create(ParseErrorCode.InvalidFormat, reason), rawInput);
    }

    public static ParseResult<T> Failure(ParseErrorCode code, string message, string? rawInput = null)
    {
        return new ParseResult<T>(ParseState.Error, default,
            ParseError.Create(code, message), rawInput);
    }

    // === TRANSFORMATION ===

    public ParseResult<TNew> Map<TNew>(Func<T, TNew> mapper)
    {
        if (IsSuccess && Value != null)
        {
            return ParseResult<TNew>.Success(mapper(Value), RawInput);
        }

        return new ParseResult<TNew>(State, default, Error, RawInput);
    }

    public override string ToString()
    {
        if (IsSuccess) return $"[Success] {Value}";
        return $"[{State}] {Error}";
    }
}