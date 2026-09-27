using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.7: Typed Identity Migration - join-key normalization + typed
/// join index (audit X-005: naked string joins across ~60 sites).
///
/// STRATEGY (inward-boundary migration): the central convergence point
/// (EvidenceFusionService.ResolveGroupKey) resolves group keys through
/// the normalization here, so Fusion, Consistency and Conflict agree on
/// group membership. Per the H-01.6 model map, every raw key classifies
/// into a typed TargetKey (H-01.2) - Symbol / File / Other.
///
/// NORMALIZATION RULES (v1):
///   - raw keys: trim.
///   - FILE| keys: path part trim + backslash->slash.
///   - file paths: trim + backslash->slash.
///   - whitespace-only keys count as ABSENT (never a group of their own).
///   - case is preserved (path case-folding is platform-dependent and
///     lands with H-07.6 repository-root normalization); case variants
///     are SURFACED as diagnostics by TypedJoinIndex instead of being
///     silently merged or silently split.
///
/// DEFERRED ADOPTIONS (documented, evidence-backed):
///   - EvidenceId (H-01.7.5): adopted in H-08.9 - requires the content
///     hash model; no fabrication before that.
///   - hierarchical FILE|path|L&lt;line&gt; identity: H-12 adoption of
///     KBF-14-001 (audit mapping) - grouping stays file-granular here.
/// </summary>
public static class JoinKeyNormalization
{
    /// <summary>Trim; FILE| prefixed keys get their path part slash-normalized.</summary>
    public static string NormalizeRawKey(string? rawKey)
    {
        var v = (rawKey ?? string.Empty).Trim();
        if (v.Length == 0) return string.Empty;
        if (v.StartsWith("FILE|", StringComparison.Ordinal))
            return $"FILE|{v["FILE|".Length..].Replace('\\', '/')}";
        return v;
    }

    /// <summary>File path join form: trim + backslash->slash.</summary>
    public static string NormalizePath(string? path) =>
        (path ?? string.Empty).Trim().Replace('\\', '/');

    /// <summary>
    /// Canonical fusion group key: symbol key wins; else FILE|&lt;path&gt;;
    /// else FILE|unknown. Built-in normalization guarantees that ALL
    /// consumers (Fusion / Consistency / Conflict) agree on group
    /// membership for padded and separator-variant keys.
    /// </summary>
    public static string ResolveGroupKey(string? symbolKey, string? filePath)
    {
        var symbol = (symbolKey ?? string.Empty).Trim();
        if (symbol.Length > 0) return symbol;

        var file = NormalizePath(filePath);
        return file.Length > 0 ? $"FILE|{file}" : "FILE|unknown";
    }
}

/// <summary>
/// One classified, normalized join key with its typed identity.
/// Factory instead of default property initializers: TargetKey.FromRaw
/// throws on empty input (H-01.2 contract), so a typed entry can only
/// exist for a validated non-empty key.
/// </summary>
public sealed class TypedJoinEntry
{
    public string RawKey { get; }
    public string NormalizedKey { get; }
    public TargetKey Key { get; }
    public TargetKeyKind Kind { get; }

    private TypedJoinEntry(string rawKey, string normalizedKey, TargetKey key, TargetKeyKind kind)
        => (RawKey, NormalizedKey, Key, Kind) = (rawKey, normalizedKey, key, kind);

    public static TypedJoinEntry Create(string rawKey, string normalizedKey)
    {
        var key = TargetKey.FromRaw(normalizedKey);
        return new TypedJoinEntry(rawKey, normalizedKey, key, key.Kind);
    }
}

/// <summary>
/// H-01.7: typed join index. Validates and classifies join keys, and
/// surfaces the classic string-join hazards as explicit diagnostics:
/// empty keys (skipped) and case-variant keys (grouped separately by
/// design - flagged, never silently merged).
/// </summary>
public sealed class TypedJoinIndex
{
    private readonly Dictionary<string, TypedJoinEntry> _byNormalized;
    private readonly Dictionary<string, TypedJoinEntry> _byRaw;

    public IReadOnlyList<TypedJoinEntry> Entries { get; }
    public IReadOnlyList<string> Diagnostics { get; }

    private TypedJoinIndex(
        List<TypedJoinEntry> entries,
        Dictionary<string, TypedJoinEntry> byNormalized,
        Dictionary<string, TypedJoinEntry> byRaw,
        List<string> diagnostics)
    {
        Entries = entries;
        _byNormalized = byNormalized;
        _byRaw = byRaw;
        Diagnostics = diagnostics;
    }

    public static TypedJoinIndex Build(IEnumerable<string?> rawKeys)
    {
        if (rawKeys is null) throw new ArgumentNullException(nameof(rawKeys));

        var diagnostics = new List<string>();
        var byNormalized = new Dictionary<string, TypedJoinEntry>(StringComparer.Ordinal);
        var byRaw = new Dictionary<string, TypedJoinEntry>(StringComparer.Ordinal);
        var skippedEmpty = 0;

        foreach (var raw in rawKeys)
        {
            var normalized = JoinKeyNormalization.NormalizeRawKey(raw);
            if (normalized.Length == 0)
            {
                skippedEmpty++;
                continue;
            }

            var trimmedRaw = raw!.Trim();
            if (byRaw.ContainsKey(trimmedRaw)) continue;   // duplicate raw - benign

            if (!byNormalized.TryGetValue(normalized, out var entry))
            {
                entry = TypedJoinEntry.Create(trimmedRaw, normalized);
                byNormalized[normalized] = entry;
            }
            byRaw[trimmedRaw] = entry;
        }

        if (skippedEmpty > 0)
            diagnostics.Add($"{skippedEmpty} empty join key(s) skipped");

        foreach (var group in byNormalized.Values
                     .GroupBy(e => e.NormalizedKey, StringComparer.OrdinalIgnoreCase)
                     .Where(g => g.Count() > 1))
        {
            diagnostics.Add(
                "case-variant join keys detected: " +
                string.Join(", ", group
                    .Select(e => $"'{e.NormalizedKey}'")
                    .OrderBy(s => s, StringComparer.Ordinal)) +
                " (grouping preserves case; path case-folding lands with H-07.6)");
        }

        return new TypedJoinIndex(
            byNormalized.Values
                .OrderBy(e => e.NormalizedKey, StringComparer.Ordinal)
                .ToList(),
            byNormalized, byRaw, diagnostics);
    }

    /// <summary>Lookup by raw (padded) form - normalization applied on lookup.</summary>
    public bool TryGetByRaw(string rawKey, [NotNullWhen(true)] out TypedJoinEntry? entry)
    {
        entry = null;
        if (string.IsNullOrWhiteSpace(rawKey)) return false;
        return _byRaw.TryGetValue(rawKey.Trim(), out entry);
    }

    /// <summary>Two raw keys join when they normalize to the same form.</summary>
    public bool CanJoin(string? rawA, string? rawB)
    {
        var a = JoinKeyNormalization.NormalizeRawKey(rawA);
        var b = JoinKeyNormalization.NormalizeRawKey(rawB);
        return a.Length > 0 && a == b;
    }

    public int CountByKind(TargetKeyKind kind) => Entries.Count(e => e.Kind == kind);
}