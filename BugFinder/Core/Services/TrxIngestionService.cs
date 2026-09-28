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
/// H-03.5: TRX Ingestion Service.
/// Stage 3.5.1  test definition identity (UnitTestResult + TestDefinitions)
/// Stage 3.5.2  ACTUAL assembly identity from @storage/@codeBase —
///              NEVER a hard-coded name (KBF-01-006)
/// Stage 3.5.3-3.5.6  real timestamps from XML attributes — missing
///              attributes become null (X-004: not zero)
/// Stage 3.5.7  unknown test definitions PRESERVED (KBF-01-005)
///
/// RESULT SHAPE (H-01.8): Success (records), Corrupt (bad XML — reason
/// mandatory), FileMissing (explicit), NoResults (parsed, zero records —
/// explicit, never fabricated as success).
/// </summary>
public class TrxIngestionService
{
    private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ss.FFFK";

    public TrxIngestionReport Ingest(string trxPath)
    {
        if (string.IsNullOrWhiteSpace(trxPath))
            throw new ArgumentException("TRX path is required.", nameof(trxPath));

        var fullPath = Path.GetFullPath(trxPath);
        if (!File.Exists(fullPath))
            return new TrxIngestionReport
            {
                Status = TrxIngestionStatus.FileMissing,
                SourceArtifactPath = fullPath,
                Reason = $"TRX artifact not found on disk: '{fullPath}'"
            };

        XDocument document;
        try
        {
            document = XDocument.Load(fullPath);
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or IOException)
        {
            return new TrxIngestionReport
            {
                Status = TrxIngestionStatus.Corrupt,
                SourceArtifactPath = fullPath,
                Reason = $"TRX unreadable: {ex.Message} (corruption evidence preserved — H-06.4.4)"
            };
        }

        var diagnostics = new List<string>();

        var root = document.Root;
        if (root?.Name.LocalName != "TestRun")
            return new TrxIngestionReport
            {
                Status = TrxIngestionStatus.Corrupt,
                SourceArtifactPath = fullPath,
                Reason = "root element is not TestRun"
            };

        // Run metadata (optional)
        var times = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Times");
        var runStarted = ParseTimestamp(times?.Attribute("start")?.Value);
        var runFinished = ParseTimestamp(times?.Attribute("finish")?.Value);

        // TestDefinitions — executionId → (name, storage)
        var definitions = root.Descendants()
            .Where(e => e.Name.LocalName == "UnitTest")
            .Select(e => new
            {
                ExecutionId = e.Attribute("id")?.Value ?? string.Empty,
                Name = e.Attribute("name")?.Value ?? string.Empty,
                Storage = e.Attributes().FirstOrDefault(a => a.Name.LocalName == "storage")?.Value
    ?? e.Attributes().FirstOrDefault(a => a.Name.LocalName == "codeBase")?.Value
    ?? e.Descendants().FirstOrDefault(d => d.Name.LocalName == "TestMethod")?
        .Attributes().FirstOrDefault(a => a.Name.LocalName == "storage")?.Value
    ?? e.Descendants().FirstOrDefault(d => d.Name.LocalName == "TestMethod")?
        .Attributes().FirstOrDefault(a => a.Name.LocalName == "codeBase")?.Value
            }) 
            .Where(d => d.ExecutionId.Length > 0)
            .ToDictionary(d => d.ExecutionId, StringComparer.Ordinal);

        // Results
        var resultElements = root.Descendants()
            .Where(e => e.Name.LocalName == "UnitTestResult")
            .ToList();

        if (resultElements.Count == 0)
            return new TrxIngestionReport
            {
                Status = TrxIngestionStatus.NoResults,
                SourceArtifactPath = fullPath,
                Reason = "TRX parsed but contains zero UnitTestResult elements",
                RunStartedUtc = runStarted,
                RunFinishedUtc = runFinished
            };

        var records = new List<TrxTestRecord>();
        var unknownDefinitions = 0;

        foreach (var result in resultElements)
        {
            var executionId = result.Attribute("executionId")?.Value ?? string.Empty;
            var resultTestName = result.Attribute("testName")?.Value ?? string.Empty;

            definitions.TryGetValue(executionId, out var definition);
            var isUnknown = definition is null;

            if (isUnknown)
            {
                // Stage 3.5.7 — PRESERVED, not skipped (KBF-01-005)
                unknownDefinitions++;
                diagnostics.Add($"unknown definition preserved: executionId='{executionId}'");
            }

            var started = ParseTimestamp(result.Attribute("startTime")?.Value);
            var completed = ParseTimestamp(result.Attribute("endTime")?.Value);
            var duration = ParseDuration(result.Attribute("duration")?.Value);

            records.Add(new TrxTestRecord
            {
                ExecutionId = executionId,
                TestName = resultTestName,
                TestFullName = definition?.Name ?? resultTestName,
                AssemblyPath = JoinKeyNormalization.NormalizePath(
                    definition?.Storage ?? string.Empty),
                Outcome = result.Attribute("outcome")?.Value ?? string.Empty,
                StartedUtc = started,
                CompletedUtc = completed,
                Duration = duration,
                IsUnknownDefinition = isUnknown
            });
        }

        return new TrxIngestionReport
        {
            Status = TrxIngestionStatus.Ingested,
            SourceArtifactPath = fullPath,
            Records = records
                .OrderBy(r => r.CompletedUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(r => r.TestFullName, StringComparer.Ordinal)
                .ToList(),
            UnknownDefinitionCount = unknownDefinitions,
            Diagnostics = diagnostics,
            RunStartedUtc = runStarted,
            RunFinishedUtc = runFinished
        };
    }

    // ---------- internals ----------

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;   // X-004: absent ≠ zero
        if (DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
            return parsed;
        return null;
    }

    private static TimeSpan? ParseDuration(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }
}