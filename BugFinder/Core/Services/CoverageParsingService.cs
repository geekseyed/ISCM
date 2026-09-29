using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-04.2: Coverage Parsing Service.
/// Parses the coverlet cobertura XML into a structured CoverageDocument.
///
/// Stage 4.2.1  format detection: root element MUST be "coverage" with
///              a line-rate attribute — otherwise UnsupportedFormat
///              (explicit, never guessed — audit KBF-06-002).
/// Stage 4.2.2  modules: coverage/modules/module/@name.
/// Stage 4.2.3  classes: module/classes/class/@name + @filename.
/// Stage 4.2.4  methods: class/methods/method/@name + @signature.
/// Stage 4.2.5  lines: method/lines/line/@number + @hits + @condition-coverage
///              — REAL per-line hit counts (the raw spectrum material).
/// Stage 4.2.6  source artifact identity: SourceArtifactPath carried on
///              the document (hash lands in H-08.9).
///
/// Namespace-agnostic (LocalName matching) — coverlet emits default-
/// namespace XML; explicit namespace handling would be brittle.
/// Number parsing uses InvariantCulture (XML format is locale-independent).
/// </summary>
public class CoverageParsingService
{
    public CoverageDocument Parse(string artifactPath)
    {
        if (string.IsNullOrWhiteSpace(artifactPath))
            throw new ArgumentException("Coverage artifact path is required.", nameof(artifactPath));

        var fullPath = Path.GetFullPath(artifactPath);
        if (!File.Exists(fullPath))
            return Fail(fullPath, CoverageParsingStatus.FileMissing,
                $"coverage artifact not found on disk: '{fullPath}'");

        XDocument document;
        try
        {
            document = XDocument.Load(fullPath);
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or IOException)
        {
            return Fail(fullPath, CoverageParsingStatus.Corrupt,
                $"coverage artifact unreadable: {ex.Message} (corruption evidence preserved)");
        }

        var root = document.Root;
        if (root is null || root.Name.LocalName != "coverage")
            return Fail(fullPath, CoverageParsingStatus.UnsupportedFormat,
                $"root element is '{root?.Name.LocalName ?? "null"}', expected 'coverage' " +
                "(format detection is explicit — audit KBF-06-002)");

        if (root.Attribute("line-rate") is null)
            return Fail(fullPath, CoverageParsingStatus.UnsupportedFormat,
                "coverage root is missing the line-rate attribute — not a cobertura document");

        var modules = root.Descendants()
            .Where(e => e.Name.LocalName == "module")
            .Select(ParseModule)
            .ToList();

        if (modules.Count == 0)
            return Fail(fullPath, CoverageParsingStatus.NoModules,
                "coverage document contains zero module elements");

        var totalLines = modules.Sum(m => m.Classes.Sum(c => c.AllLines.Count));
        var coveredLines = modules.Sum(m => m.Classes.Sum(c => c.AllLines.Count(l => l.IsCovered)));

        return new CoverageDocument
        {
            Status = CoverageParsingStatus.Parsed,
            SourceArtifactPath = fullPath,
            Modules = modules.OrderByDescending(m => m.ModuleName, StringComparer.Ordinal).ToList(),
            TotalModules = modules.Count,
            TotalClasses = modules.Sum(m => m.Classes.Count),
            TotalMethods = modules.Sum(m => m.Classes.Sum(c => c.Methods.Count)),
            TotalLines = totalLines,
            CoveredLines = coveredLines,
            LineRate = totalLines == 0 ? 0m : (decimal)coveredLines / totalLines
        };
    }

    // ---------- internals ----------

    private static CoverageModule ParseModule(XElement moduleElement)
    {
        var classes = moduleElement.Descendants()
            .Where(e => e.Name.LocalName == "class")
            .Select(ParseClass)
            .OrderBy(c => c.ClassName, StringComparer.Ordinal)
            .ToList();

        return new CoverageModule
        {
            ModuleName = moduleElement.Attribute("name")?.Value ?? string.Empty,
            Classes = classes
        };
    }

    private static CoverageClass ParseClass(XElement classElement)
    {
        var methods = classElement.Descendants()
            .Where(e => e.Name.LocalName == "method")
            .Select(ParseMethod)
            .OrderBy(m => m.Signature, StringComparer.Ordinal)
            .ToList();

        // flatten lines across methods, dedupe by line number (keep max hits)
        var allLines = methods
            .SelectMany(m => m.Lines)
            .GroupBy(l => l.LineNumber)
            .Select(g => g.OrderByDescending(l => l.Hits).First())
            .OrderBy(l => l.LineNumber)
            .ToList();

        return new CoverageClass
        {
            ClassName = classElement.Attribute("name")?.Value ?? string.Empty,
            SourceFilePath = JoinKeyNormalization.NormalizePath(
                classElement.Attribute("filename")?.Value ?? string.Empty),
            LineRate = ParseDecimal(classElement.Attribute("line-rate")?.Value),
            Methods = methods,
            AllLines = allLines
        };
    }

    private static CoverageMethod ParseMethod(XElement methodElement)
    {
        var lines = methodElement.Descendants()
            .Where(e => e.Name.LocalName == "line")
            .Select(ParseLine)
            .OrderBy(l => l.LineNumber)
            .ToList();

        return new CoverageMethod
        {
            MethodName = methodElement.Attribute("name")?.Value ?? string.Empty,
            Signature = methodElement.Attribute("signature")?.Value ?? string.Empty,
            LineRate = ParseDecimal(methodElement.Attribute("line-rate")?.Value),
            Lines = lines
        };
    }

    private static CoverageLine ParseLine(XElement lineElement)
    {
        return new CoverageLine
        {
            LineNumber = ParseInt(lineElement.Attribute("number")?.Value),
            Hits = ParseInt(lineElement.Attribute("hits")?.Value),
            ConditionCoverage = lineElement.Attribute("condition-coverage")?.Value
        };
    }

    private static int ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed : 0;

    private static decimal ParseDecimal(string? value) =>
        decimal.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
            ? parsed : 0m;

    private static CoverageDocument Fail(string path, CoverageParsingStatus status, string reason) =>
        new()
        {
            Status = status,
            SourceArtifactPath = path,
            Reason = reason
        };
}