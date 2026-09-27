using System;
using System.Collections.Generic;
using System.Text.Json;
using ISCM.BugFinder.Core.Contracts;

namespace ISCM.BugFinder.Core.Services;

/// <summary>
/// H-01.1: Baseline Manifest Service.
/// Stage 1.1.1-1.1.3: Build — captures repository identity, executable
///          state and test execution into one manifest.
/// Stage 1.1.4: Verify — compares the stored manifest against current
///          actuals; any branch/commit/count mismatch becomes an
///          explicit stale-reference finding and fails the gate.
/// Stage 1.1.5: Reproducibility — the counts comparison IS the re-run
///          check; the actual re-run execution is performed by the
///          caller (dotnet test) and fed in as actuals.
/// Deterministic: pure inputs in, pure outputs out; JSON via
/// System.Text.Json (round-trip gate seed for H-01.9.2).
/// </summary>
public class BaselineManifestService
{
    public BaselineManifest Build(BaselineManifestInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        return new BaselineManifest
        {
            RepositoryId = input.RepositoryId,
            Branch = input.Branch,
            CommitSha = input.CommitSha,
            RecordedAtUtc = input.RecordedAtUtc,
            AuditedHeadSha = input.AuditedHeadSha,
            SolutionName = input.SolutionName,
            TargetFramework = input.TargetFramework,
            TestFramework = input.TestFramework,
            TestSdkVersion = input.TestSdkVersion,
            BuildConfiguration = input.BuildConfiguration,
            TestCommand = input.TestCommand,
            ResultArtifactPath = input.ResultArtifactPath,
            PassedCount = input.PassedCount,
            FailedCount = input.FailedCount,
            SkippedCount = input.SkippedCount,
            ExecutionDuration = input.ExecutionDuration
        };
    }

    public string Serialize(BaselineManifest manifest)
    {
        if (manifest is null) throw new ArgumentNullException(nameof(manifest));
        return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
    }

    public BaselineManifest? Deserialize(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("Manifest JSON is required.", nameof(json));
        return JsonSerializer.Deserialize<BaselineManifest>(json);
    }

    /// <summary>
    /// H-01.1.4 + H-01.1.5: compares a stored manifest against the
    /// current actual state. Every mismatch is an explicit finding —
    /// a stale baseline can never silently pass.
    /// </summary>
    public BaselineVerificationReport Verify(
        BaselineManifest manifest,
        string actualBranch,
        string actualCommitSha,
        int actualPassedCount,
        int actualFailedCount,
        int actualSkippedCount)
    {
        if (manifest is null) throw new ArgumentNullException(nameof(manifest));

        var findings = new List<string>();

        // H-01.3 seed — incompatible persisted schema
        if (manifest.SchemaVersion != BaselineManifest.CurrentSchemaVersion)
        {
            return new BaselineVerificationReport
            {
                Status = BaselineMatchStatus.Incomparable,
                StaleReferences =
                {
                    $"schema version mismatch: manifest=v{manifest.SchemaVersion}, " +
                    $"current=v{BaselineManifest.CurrentSchemaVersion}"
                }
            };
        }

        if (!string.Equals(manifest.Branch, actualBranch, StringComparison.Ordinal))
            findings.Add($"stale branch reference: manifest='{manifest.Branch}', actual='{actualBranch}'");

        if (!string.Equals(manifest.CommitSha, actualCommitSha, StringComparison.OrdinalIgnoreCase))
            findings.Add($"stale commit reference: manifest='{manifest.CommitSha}', actual='{actualCommitSha}'");

        if (manifest.PassedCount != actualPassedCount
            || manifest.FailedCount != actualFailedCount
            || manifest.SkippedCount != actualSkippedCount)
        {
            findings.Add(
                "non-reproducible test execution: " +
                $"manifest=(passed {manifest.PassedCount}, failed {manifest.FailedCount}, skipped {manifest.SkippedCount}), " +
                $"actual=(passed {actualPassedCount}, failed {actualFailedCount}, skipped {actualSkippedCount})");
        }

        return new BaselineVerificationReport
        {
            Status = findings.Count == 0 ? BaselineMatchStatus.Identical : BaselineMatchStatus.Different,
            StaleReferences = findings
        };
    }
}