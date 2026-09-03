using System;
using System.Collections.Generic;
using System.Linq;
using ISCM.Domain.Entities;
using ISCM.Domain.Interfaces;

namespace ISCM.Domain.Services;

/// <summary>
/// Validates evidence isolation and detects cross-contamination.
/// </summary>
public class EvidenceScopeValidator
{
    public ValidationResult ValidateEvidenceScope(Evidence evidence)
    {
        if (string.IsNullOrEmpty(evidence.ScanId))
            return ValidationResult.Fail("Evidence.ScanId is required.");

        if (string.IsNullOrEmpty(evidence.SubControlId))
            return ValidationResult.Fail("Evidence.SubControlId is required.");

        if (string.IsNullOrEmpty(evidence.Fingerprint))
            return ValidationResult.Fail("Evidence.Fingerprint is required.");

        return ValidationResult.Success();
    }

    public ValidationResult ValidateEvidenceCollection(IEnumerable<Evidence> evidenceCollection)
    {
        var errors = new List<string>();

        foreach (var evidence in evidenceCollection)
        {
            var result = ValidateEvidenceScope(evidence);
            if (!result.IsValid)
                errors.AddRange(result.Errors);
        }

        return errors.Any()
            ? ValidationResult.Fail(errors.ToArray())
            : ValidationResult.Success();
    }

    public CrossContaminationReport DetectCrossContamination(IEnumerable<Evidence> evidenceCollection)
    {
        var report = new CrossContaminationReport();

        var grouped = evidenceCollection
            .GroupBy(e => new { e.ScanId, e.SubControlId, e.PathId });

        foreach (var group in grouped)
        {
            var fingerprints = group.Select(e => e.Fingerprint).ToList();
            var duplicates = fingerprints
                .GroupBy(f => f)
                .Where(g => g.Count() > 1)
                .Select(g => g.Key)
                .ToList();

            if (duplicates.Any())
            {
                report.AddDuplicate(group.Key.ScanId, group.Key.SubControlId, duplicates);
            }
        }

        // Check for evidence used across multiple SubControls
        var byFingerprint = evidenceCollection
            .GroupBy(e => e.Fingerprint)
            .Where(g => g.Select(e => e.SubControlId).Distinct().Count() > 1);

        foreach (var group in byFingerprint)
        {
            report.AddCrossSubControlUsage(
                group.Key,
                group.Select(e => e.SubControlId).Distinct().ToList());
        }

        return report;
    }
}

public class ValidationResult
{
    public bool IsValid { get; private set; }
    public List<string> Errors { get; private set; } = new();

    public static ValidationResult Success() => new() { IsValid = true };

    public static ValidationResult Fail(params string[] errors)
    {
        var result = new ValidationResult { IsValid = false };
        result.Errors.AddRange(errors);
        return result;
    }
}

public class CrossContaminationReport
{
    public bool HasContamination => DuplicateFingerprints.Any() || CrossSubControlUsage.Any();

    public List<(string ScanId, string SubControlId, List<string> Fingerprints)> DuplicateFingerprints { get; } = new();
    public List<(string Fingerprint, List<string> SubControlIds)> CrossSubControlUsage { get; } = new();

    public void AddDuplicate(string scanId, string subControlId, List<string> fingerprints)
        => DuplicateFingerprints.Add((scanId, subControlId, fingerprints));

    public void AddCrossSubControlUsage(string fingerprint, List<string> subControlIds)
        => CrossSubControlUsage.Add((fingerprint, subControlIds));
}