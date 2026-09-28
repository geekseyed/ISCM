using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-02.2: Failure Signature Generation.
/// Derives the deterministic FailureSignature (H-01.2 contract) from a
/// FailureSignatureMaterial (H-02.1).
///
/// STAGES:
///   2.2.1-2.2.4  test/assertion/exception/location sections normalize
///                through the canonical form below (frame-level stack
///                normalization arrives with the H-03 parser adoption).
///   2.2.5        message volatility absorbed: GUIDs, long hex blobs,
///                timestamps, paths -> placeholders.
///   2.2.6        meaningful magnitude preserved: numbers bucket to the
///                NEAREST power of two - 511 and 512 land in one bucket
///                (run-to-run jitter absorbed), 512 vs 1024 stay distinct
///                ("expected 512, actual 1024" keeps its meaning).
///   2.2.7        signature = SHA-256 over the canonical form, emitted
///                as FS-&lt;64 lowercase hex&gt;; FailureId derived as
///                F-&lt;same hex&gt; (same failure -> same id).
///
/// DETERMINISM: no randomness, no clock, no Guid - the hash input is a
/// versioned canonical form ("sigv1|...") containing EVERY section, with
/// unknown sections marked &lt;ABSENT&gt; - so "empty message" and "no
/// message" never collapse (H-01.4: Empty != Missing, at signature level).
/// Case is preserved (pinned by test): message casing may be meaningful.
/// Normalization-scheme changes bump the sigv prefix - old signatures
/// stay comparable within their scheme.
/// </summary>
public class FailureSignatureService
{
    private const string SchemeVersion = "sigv1";

    private static readonly Regex GuidPattern =
        new(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.Compiled);

    private static readonly Regex TimestampPattern =
        new(@"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?", RegexOptions.Compiled);

    private static readonly Regex LongHexPattern =
        new(@"\b[0-9a-fA-F]{16,}\b", RegexOptions.Compiled);

    private static readonly Regex BackslashPathPattern =
        new(@"[^\s]*\\[^\s]*", RegexOptions.Compiled);

    private static readonly Regex DrivePathPattern =
        new(@"(?<=^|\s)[A-Za-z]:[^\s]*", RegexOptions.Compiled);

    private static readonly Regex UnixPathPattern =
        new(@"(?<=^|\s)/[^\s]+", RegexOptions.Compiled);

    private static readonly Regex NumberPattern =
        new(@"-?\d+(?:\.\d+)?", RegexOptions.Compiled);

    private static readonly Regex WhitespacePattern =
        new(@"\s+", RegexOptions.Compiled);

    /// <summary>Generate: material -> signature + derived failure id.</summary>
    public FailureSignatureDerivation Generate(FailureSignatureMaterial material)
    {
        if (material is null) throw new ArgumentNullException(nameof(material));
        if (!material.HasAnyKnowledge)
            throw new ArgumentException(
                "Cannot derive a failure signature from zero knowledge " +
                "(H-01.4: no fabrication). At least one material section must carry information.",
                nameof(material));

        var canonical = BuildCanonicalForm(material);
        var hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
                        .ToLowerInvariant();

        return new FailureSignatureDerivation
        {
            Signature = FailureSignature.Create($"FS-{hex}"),
            FailureId = FailureId.Create($"F-{hex}"),
            CanonicalForm = canonical
        };
    }

    // ---------- canonical form (the hash input) ----------

    private static string BuildCanonicalForm(FailureSignatureMaterial m)
    {
        var sb = new StringBuilder();
        sb.Append(SchemeVersion).Append('|');

        // 2.2.1 — test identity (all three parts empty => ABSENT).
        // NOTE: check the identity FIELDS directly - string.All() walks
        // characters, not the pipe-separated segments.
        var hasTest = m.TestIdentity.AssemblyName.Length > 0
                      || m.TestIdentity.ClassName.Length > 0
                      || m.TestIdentity.TestName.Length > 0;
        var test = $"{m.TestIdentity.AssemblyName}|{m.TestIdentity.ClassName}|{m.TestIdentity.TestName}";
        AppendSection(sb, "test", hasTest ? test : null);

        // 2.2.2 — assertion metadata
        var hasAssertion = m.AssertionType is not null || m.AssertionMessage is not null;
        AppendSection(sb, "assertion", hasAssertion
            ? $"{m.AssertionType ?? string.Empty}|{NormalizeMessage(m.AssertionMessage ?? string.Empty)}"
            : null);

        // 2.2.3 — exception identity + inner chain (order preserved)
        var hasException = m.ExceptionTypeName is not null || m.InnerExceptionTypeNames.Count > 0;
        AppendSection(sb, "exception", hasException
            ? $"{m.ExceptionTypeName ?? string.Empty}|{string.Join(">", m.InnerExceptionTypeNames)}"
            : null);

        // 2.1.4 — domain section
        var hasDomain = m.SubControlId is not null || m.DomainStatus.HasValue;
        AppendSection(sb, "domain", hasDomain
            ? $"{m.SubControlId ?? string.Empty}|{(m.DomainStatus.HasValue ? m.DomainStatus.Value.ToString() : string.Empty)}"
            : null);

        // 2.2.4 — source location (path slash-normalized via H-01.7 rules)
        AppendSection(sb, "location", m.Location is null
            ? null
            : $"{JoinKeyNormalization.NormalizePath(m.Location.FilePath)}|"
              + $"L{(m.Location.LineNumber?.ToString() ?? string.Empty)}|{m.Location.MethodName ?? string.Empty}");

        // 2.2.5/2.2.6 — message (null = ABSENT; "" = empty message, distinct!)
        AppendSection(sb, "message", m.RawMessage is null ? null : NormalizeMessage(m.RawMessage));

        // 2.1.7 — execution context
        AppendSection(sb, "environment",
            string.IsNullOrWhiteSpace(m.EnvironmentFingerprint) ? null : m.EnvironmentFingerprint.Trim());

        return sb.ToString();
    }

    private static void AppendSection(StringBuilder sb, string name, string? content) =>
        sb.Append(name).Append('=').Append(content ?? "<ABSENT>").Append('\n');

    // ---------- message normalization (stages 2.2.5 + 2.2.6) ----------

    /// <summary>
    /// v1 normalization: trim, collapse whitespace, then absorb volatile
    /// tokens (GUID / timestamp / long hex / paths) and bucket numbers to
    /// the nearest power of two. Case is preserved (pinned by test).
    /// Known v1 limitation: comma-grouped numbers ("1,237") tokenize as
    /// two numbers - documented, deterministic, refine in H-03 adoption.
    /// </summary>
    public static string NormalizeMessage(string message)
    {
        var v = WhitespacePattern.Replace(message ?? string.Empty, " ").Trim();

        v = GuidPattern.Replace(v, "<GUID>");
        v = TimestampPattern.Replace(v, "<TS>");
        v = LongHexPattern.Replace(v, "<HEX>");
        v = BackslashPathPattern.Replace(v, "<PATH>");
        v = DrivePathPattern.Replace(v, "<PATH>");
        v = UnixPathPattern.Replace(v, "<PATH>");
        v = NumberPattern.Replace(v, m => Bucketize(m.Value));

        return v;
    }

    /// <summary>Nearest power of two bucket (sign preserved outside the bucket).</summary>
    private static string Bucketize(string numberText)
    {
        var negative = numberText.StartsWith('-');
        var numeric = numberText.TrimStart('-');

        if (!double.TryParse(numeric, System.Globalization.CultureInfo.InvariantCulture, out var value))
            return $"<N~{numeric}>";

        if (value == 0) return "<N~0>";
        if (Math.Abs(value) >= 1e15)
            return negative ? "-<N~HUGE>" : "<N~HUGE>";

        var exponent = (int)Math.Round(Math.Log2(Math.Abs(value)), MidpointRounding.AwayFromZero);
        var bucket = Math.Pow(2, exponent);
        var rendered = bucket.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);

        return negative ? $"-<N~{rendered}>" : $"<N~{rendered}>";
    }
}

/// <summary>The derivation output: typed signature + derived failure id + audit form.</summary>
public sealed class FailureSignatureDerivation
{
    /// <summary>FS-&lt;64 hex&gt; — the H-01.2 contract, now live.</summary>
    public FailureSignature Signature { get; init; } = null!;

    /// <summary>F-&lt;same hex&gt; — logical failure id, signature-derived.</summary>
    public FailureId FailureId { get; init; } = null!;

    /// <summary>The exact hash input (audit/debug — regenerate anytime).</summary>
    public string CanonicalForm { get; init; } = string.Empty;
}