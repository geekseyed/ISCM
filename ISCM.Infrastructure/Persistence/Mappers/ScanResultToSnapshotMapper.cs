using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ISCM.Application.Interfaces;
using ISCM.Application.Snapshots;
using ISCM.Domain.Entities;
using ISCM.Infrastructure.Persistence.Serialization;

namespace ISCM.Infrastructure.Persistence.Mappers;

public class ScanResultToSnapshotMapper : ISnapshotMapper
{
    public ScanSnapshot ToSnapshot(ScanResult scanResult, string? assetId = null)
    {
        if (scanResult == null) throw new ArgumentNullException(nameof(scanResult));
        if (!scanResult.CompletedAtUtc.HasValue)
            throw new InvalidOperationException("Cannot snapshot an incomplete scan.");

        var snapshot = new ScanSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            ScanId = scanResult.ScanId,
            AssetId = assetId ?? scanResult.Hostname,
            Hostname = scanResult.Hostname,
            IpAddress = scanResult.IpAddress,
            MacAddress = scanResult.MacAddress,
            OsVersion = scanResult.OsVersion,
            OsBuild = scanResult.OsBuild,
            ScanMode = scanResult.Mode,
            BaselineId = scanResult.BaselineId,
            BaselineName = scanResult.Baseline?.Name,
            BaselineVersion = scanResult.Baseline?.Version,
            ScannerVersion = scanResult.ScannerVersion,
            StartedAtUtc = scanResult.StartedAtUtc,
            CompletedAtUtc = scanResult.CompletedAtUtc.Value,
            OverallStatus = ComputeOverallStatus(scanResult),
            ComplianceScore = scanResult.ComplianceScore,
            Grade = scanResult.Grade,
            PassCount = scanResult.PassCount,
            FailCount = scanResult.FailCount,
            WarningCount = scanResult.WarningCount,
            ErrorCount = scanResult.Findings.Count(f => f.Status == Domain.Enums.CheckStatus.Error),
            TotalControlCount = scanResult.ControlResults.Count,
            TotalSubControlCount = scanResult.ControlResults.Sum(c => c.SubControlResults.Count),
            Controls = MapControls(scanResult.ControlResults),
            Findings = MapFindings(scanResult.Findings),
            SchemaVersion = 1
        };

        // Compute integrity hash AFTER all fields are populated
        // Use with-expression to create a copy with IntegrityHash set
        var finalSnapshot = snapshot with { IntegrityHash = ComputeIntegrityHash(snapshot) };

        return finalSnapshot;
    }

    public ScanResult ToScanResult(ScanSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));

        var scanResult = new ScanResult(
            hostname: snapshot.Hostname,
            ipAddress: snapshot.IpAddress,
            macAddress: snapshot.MacAddress,
            osVersion: snapshot.OsVersion,
            osBuild: snapshot.OsBuild.ToString(),
            mode: snapshot.ScanMode,
            targetId: snapshot.AssetId,
            scannerVersion: snapshot.ScannerVersion,
            scanId: snapshot.ScanId)
        {
            BaselineId = snapshot.BaselineId,
            StartedAtUtc = snapshot.StartedAtUtc,
            CompletedAtUtc = snapshot.CompletedAtUtc
        };

        foreach (var f in snapshot.Findings)
        {
            var finding = new Finding(
                checkId: f.CheckId,
                name: f.Name,
                category: f.Category,
                severity: f.Severity,
                status: f.Status,
                currentValue: f.CurrentValue,
                expectedValue: f.ExpectedValue,
                recommendation: f.Recommendation,
                errorMessage: f.ErrorMessage,
                description: f.Description,
                registryPath: f.RegistryPath,
                cisReference: f.CisReference,
                riskScore: f.RiskScore,
                sourceType: f.SourceType,
                sourceCommand: f.SourceCommand,
                fixTools: null,
                subChecks: null,
                subControlId: f.SubControlId
            );
            scanResult.AddFinding(finding);
        }

        foreach (var c in snapshot.Controls)
        {
            var controlResult = new ControlResult
            {
                ControlId = c.ControlId,
                ParentControlId = c.ParentControlId,
                Status = c.Status,
                EvaluatedAt = c.EvaluatedAt
            };

            foreach (var s in c.SubControls)
            {
                var subControlResult = new SubControlResult
                {
                    SubControlId = s.SubControlId,
                    Status = s.Status,
                    EvaluatedAt = s.EvaluatedAt
                };

                foreach (var e in s.EvidenceItems)
                {
                    var evidence = new Evidence
                    {
                        EvidenceId = e.EvidenceId,
                        ScanId = snapshot.ScanId,
                        ParentControlId = e.SubControlId,
                        SubControlId = e.SubControlId,
                        PathId = e.PathId,
                        TechnicalCheckId = e.TechnicalCheckId,
                        SourceType = e.SourceType,
                        SourceName = e.SourceName,
                        AcquisitionCommand = e.AcquisitionCommand,
                        AcquisitionArguments = e.AcquisitionArguments,
                        MachineIdentity = e.MachineIdentity,
                        CollectedAtUtc = e.CollectedAtUtc,
                        CollectionDurationMs = e.CollectionDurationMs,
                        RawOutput = e.RawOutput,
                        ParsedValue = e.ParsedValue,
                        NormalizedValue = e.NormalizedValue,
                        ExpectedValue = e.ExpectedValue,
                        ValueType = e.ValueType,
                        Evaluation = e.Evaluation,
                        EvaluationReason = e.EvaluationReason ?? string.Empty,
                        Error = e.Error,
                        Fingerprint = e.Fingerprint,
                        LifecycleState = e.LifecycleState
                    };
                    subControlResult.EvidenceItems.Add(evidence);
                }

                controlResult.SubControlResults.Add(subControlResult);
            }

            scanResult.ControlResults.Add(controlResult);
        }

        return scanResult;
    }

    public string ComputeIntegrityHash(ScanSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));

        var canonical = new StringBuilder();
        canonical.Append(snapshot.ScanId).Append('|');
        canonical.Append(snapshot.AssetId).Append('|');
        canonical.Append(snapshot.StartedAtUtc.ToString("O")).Append('|');
        canonical.Append(snapshot.CompletedAtUtc.ToString("O")).Append('|');
        canonical.Append(snapshot.ComplianceScore).Append('|');
        canonical.Append(snapshot.PassCount).Append('|');
        canonical.Append(snapshot.FailCount).Append('|');
        canonical.Append(snapshot.TotalControlCount).Append('|');
        canonical.Append(snapshot.TotalSubControlCount).Append('|');

        foreach (var f in snapshot.Findings.OrderBy(f => f.CheckId).ThenBy(f => f.SubControlId))
        {
            canonical.Append($"{f.CheckId}:{f.SubControlId}:{f.Status}|");
        }

        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToBase64String(bytes);
    }

    public bool VerifyIntegrity(ScanSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
        if (string.IsNullOrEmpty(snapshot.IntegrityHash)) return false;

        var computed = ComputeIntegrityHash(snapshot with { IntegrityHash = string.Empty });
        return string.Equals(computed, snapshot.IntegrityHash, StringComparison.Ordinal);
    }

    private static Domain.Enums.CheckStatus ComputeOverallStatus(ScanResult scanResult)
    {
        if (scanResult.Findings.Any(f => f.Status == Domain.Enums.CheckStatus.Error))
            return Domain.Enums.CheckStatus.Error;
        if (scanResult.Findings.Any(f => f.Status == Domain.Enums.CheckStatus.Fail))
            return Domain.Enums.CheckStatus.Fail;
        if (scanResult.Findings.Any(f => f.Status == Domain.Enums.CheckStatus.Unknown))
            return Domain.Enums.CheckStatus.Unknown;
        return Domain.Enums.CheckStatus.Pass;
    }

    private static IReadOnlyList<ControlSnapshot> MapControls(List<ControlResult> controlResults)
    {
        return controlResults.Select(c => new ControlSnapshot
        {
            ControlId = c.ControlId,
            ParentControlId = c.ParentControlId,
            Status = c.Status,
            EvaluatedAt = c.EvaluatedAt,
            SubControls = c.SubControlResults.Select(s => new SubControlSnapshot
            {
                SubControlId = s.SubControlId,
                ParentControlId = c.ControlId,
                Status = s.Status,
                EvaluatedAt = s.EvaluatedAt,
                EvidenceItems = s.EvidenceItems.Select(e => new EvidenceSnapshot
                {
                    EvidenceId = e.EvidenceId,
                    SubControlId = e.SubControlId,
                    TechnicalCheckId = e.TechnicalCheckId,
                    PathId = e.PathId,
                    SourceType = e.SourceType,
                    SourceName = e.SourceName,
                    AcquisitionCommand = e.AcquisitionCommand,
                    AcquisitionArguments = e.AcquisitionArguments,
                    MachineIdentity = e.MachineIdentity,
                    CollectedAtUtc = e.CollectedAtUtc,
                    CollectionDurationMs = e.CollectionDurationMs,
                    RawOutput = e.RawOutput,
                    ParsedValue = e.ParsedValue,
                    NormalizedValue = e.NormalizedValue,
                    ExpectedValue = e.ExpectedValue,
                    ValueType = e.ValueType,
                    Evaluation = e.Evaluation,
                    EvaluationReason = e.EvaluationReason,
                    Error = e.Error,
                    Fingerprint = e.Fingerprint,
                    LifecycleState = e.LifecycleState
                }).ToList()
            }).ToList()
        }).ToList();
    }

    private static IReadOnlyList<FindingSnapshot> MapFindings(List<Finding> findings)
    {
        return findings.Select(f => new FindingSnapshot
        {
            CheckId = f.CheckId,
            SubControlId = f.SubControlId,
            Name = f.Name,
            Category = f.Category,
            Severity = f.Severity,
            Status = f.Status,
            CurrentValue = f.CurrentValue,
            ExpectedValue = f.ExpectedValue,
            Description = f.Description,
            RegistryPath = f.RegistryPath,
            Recommendation = f.Recommendation,
            ErrorMessage = f.ErrorMessage,
            CisReference = f.CisReference,
            RiskScore = f.RiskScore,
            SourceType = f.SourceType,
            SourceCommand = f.SourceCommand,
            IsSuppressed = f.IsSuppressed,
            IgnoreReason = f.IgnoreReason,
            IgnoredBy = f.IgnoredBy,
            IgnoredAt = f.IgnoredAt,
            IsFalsePositive = f.IsFalsePositive
        }).ToList();
    }
}