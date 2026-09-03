namespace ISCM.Domain.ValueObjects;

public enum ParseErrorCode
{
    None = 0,
    KeyNotFound = 1,
    AccessDenied = 2,
    InvalidFormat = 3,
    MissingSection = 4,
    MissingPolicy = 5,
    MissingCategory = 6,
    Timeout = 7,
    InvalidOutput = 8,
    TypeMismatch = 9,
    UnexpectedError = 10
}

public class ParseError
{
    public ParseErrorCode Code { get; }
    public string Message { get; }
    public string? Details { get; }
    public DateTime OccurredAtUtc { get; }

    private ParseError(ParseErrorCode code, string message, string? details)
    {
        Code = code;
        Message = message;
        Details = details;
        OccurredAtUtc = DateTime.UtcNow;
    }

    public static ParseError Create(ParseErrorCode code, string message, string? details = null)
    {
        return new ParseError(code, message, details);
    }

    public override string ToString()
    {
        return $"[{Code}] {Message}" + (Details != null ? $" | {Details}" : "");
    }
}