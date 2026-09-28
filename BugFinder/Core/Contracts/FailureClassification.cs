using ISCM.BugFinder.Core.Models;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-02.6: Failure Severity Separation (audit KBF-02-010: failure types
/// had no normalized severity/confidence/uncertainty dimensions, so
/// downstream ranking lacked consistent semantics).
///
/// FOUR INDEPENDENT DIMENSIONS (any legal combination is accepted —
/// independence is pinned by tests):
///   Classification : WHAT KIND of failure (FailureType, BF-02 vocabulary)
///   Severity       : HOW BAD when it happens (impact; assigned, not derived)
///   Confidence     : HOW WELL SUPPORTED the claim is (uncalibrated
///                    support value 0..1; calibration/terminology = H-09.6)
///   Applicability  : knowledge state (EvidenceState, H-01.4)
///
/// NO AUTOMATIC TYPE→SEVERITY MAPPING, by design: re-merging them is
/// exactly the defect this contract repairs. Downstream ranking may map
/// explicitly — as policy, never as contract.
///
/// SEMANTIC GUARDS:
///   - H-01.4.9: a NotApplicable classification cannot carry a real
///     severity or a confidence (NotApplicable != Failure).
///   - Process states (Missing/Derived/Unavailable/Corrupt) describe the
///     classification PROCESS, not the outcome - a classification record
///     either exists (Observed/Unknown/NotApplicable) or the service
///     returns ServiceResult (H-01.8). Those four states are refused.
///
/// RANK: severity exposes a total order for downstream ranking:
/// Unknown &lt; Informational &lt; Low &lt; Medium &lt; High &lt; Critical.
/// </summary>
public enum FailureSeverity
{
    Unknown = 0,        // not assessed (H-01.4: Unknown, not zero)
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

public static class FailureSeverityRank
{
    public static int Of(FailureSeverity severity) => (int)severity;

    /// <summary>Downstream threshold checks (e.g. gate on &gt;= Medium).</summary>
    public static bool IsAtLeast(FailureSeverity severity, FailureSeverity threshold) =>
        Of(severity) >= Of(threshold);
}

public sealed record FailureClassification
{
    public FailureType Type { get; init; }
    public FailureSeverity Severity { get; init; }
    public double? Confidence { get; init; }                 // uncalibrated support 0..1
    public EvidenceState Applicability { get; init; } = EvidenceState.Observed;

    public static FailureClassification Create(
        FailureType type,
        FailureSeverity severity,
        double? confidence = null,
        EvidenceState applicability = EvidenceState.Observed)
    {
        switch (applicability)
        {
            case EvidenceState.Observed:
            case EvidenceState.Unknown:
                break;

            case EvidenceState.NotApplicable:
                if (severity != FailureSeverity.Unknown)
                    throw new ArgumentException(
                        "A NotApplicable classification cannot carry a real severity " +
                        "(H-01.4.9: NotApplicable != Failure). Use Unknown.", nameof(severity));
                if (confidence is not null)
                    throw new ArgumentException(
                        "A NotApplicable classification cannot carry a confidence " +
                        "(H-01.4.9: NotApplicable != Failure).", nameof(confidence));
                break;

            default:
                throw new ArgumentException(
                    $"EvidenceState '{applicability}' describes the classification PROCESS, " +
                    "not an outcome. A classification record exists only for " +
                    "Observed/Unknown/NotApplicable; process states belong to " +
                    "ServiceResult (H-01.8).", nameof(applicability));
        }

        if (confidence.HasValue
            && (confidence.Value < 0.0 || confidence.Value > 1.0))
            throw new ArgumentOutOfRangeException(nameof(confidence),
                "Confidence is an uncalibrated support value in [0, 1].");

        return new FailureClassification
        {
            Type = type,
            Severity = severity,
            Confidence = confidence,
            Applicability = applicability
        };
    }
}