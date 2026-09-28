using ISCM.BugFinder.Core.Contracts;
using ISCM.BugFinder.Core.Services;

namespace ISCM.BugFinder.Core.Models;

/// <summary>
/// H-02.3: Failure Instance — one CONCRETE occurrence of a failure.
///
/// Layering (H-02 model map):
///   FailureSignature  (H-02.2) = the LOGICAL failure (content-derived,
///                                 session-independent)
///   FailureInstance   (H-02.3) = the PHYSICAL occurrence - signature +
///                                 session + definition + artifact + time
///
/// Stage map:
///   2.3.1  FailureInstanceId  - typed composite from H-01.2, derived
///                               deterministically from (signature, session)
///   2.3.2  ExecutionSessionId - mandatory; a sessionless occurrence
///                               cannot be linked, replayed or audited
///   2.3.3  TestDefinitionId   - canonical test identity + the definition
///                               string the runner reported
///   2.3.4  Source artifact    - the TRX/result artifact this instance
///                               came from (deepens into H-08.2)
///   2.3.5  OccurredAtUtc      - OBSERVED time, supplied by the caller -
///                               the Core never reads a clock (X-003;
///                               H-13.3 injects a Clock for orchestration)
///
/// The material is retained: the instance is EVIDENCE (H-08 adoption) and
/// its derivation stays reproducible.
/// </summary>
public sealed class FailureInstance
{
    /// <summary>Stage 2.3.1 — FI|&lt;FailureId&gt;|&lt;ExecutionSessionId&gt;.</summary>
    public FailureInstanceId InstanceId { get; init; } = null!;

    /// <summary>The logical failure (content-derived, session-independent).</summary>
    public FailureSignature Signature { get; init; } = null!;

    /// <summary>Signature-derived logical id (F-&lt;hex&gt;).</summary>
    public FailureId FailureId { get; init; } = null!;

    /// <summary>Stage 2.3.2 — the session this occurrence belongs to.</summary>
    public ExecutionSessionId Session { get; init; } = null!;

    /// <summary>H-02.1 material — retained evidence; derivation reproducible.</summary>
    public FailureSignatureMaterial Material { get; init; } = new();

    /// <summary>
    /// Stage 2.3.3 — the runner-reported test definition (full name).
    /// Defaults to the material's identity; a DIFFERENT value is allowed
    /// when the runner reports a distinct definition id.
    /// </summary>
    public string TestDefinitionId { get; init; } = string.Empty;

    /// <summary>Stage 2.3.4 — result artifact the instance came from.</summary>
    public string? SourceArtifact { get; init; }

    /// <summary>Stage 2.3.5 — OBSERVED occurrence time (caller-supplied).</summary>
    public DateTimeOffset OccurredAtUtc { get; init; }
}

/// <summary>
/// H-02.3 factory: composes a FailureInstance from a material (H-02.1),
/// a derived signature (H-02.2) and the occurrence context. All inputs
/// explicit - no clock, no Guid generation inside the Core.
/// </summary>
public static class FailureInstanceFactory
{
    public static FailureInstance Create(
        FailureSignatureMaterial material,
        FailureSignatureDerivation derivation,
        ExecutionSessionId session,
        DateTimeOffset occurredAtUtc,
        string? sourceArtifact = null,
        string? testDefinitionOverride = null)
    {
        if (material is null) throw new ArgumentNullException(nameof(material));
        if (derivation is null) throw new ArgumentNullException(nameof(derivation));
        if (session is null) throw new ArgumentNullException(nameof(session));

        // Stage 2.3.1 — deterministic composite id (H-01.2)
        var instanceId = FailureInstanceId.Create(derivation.FailureId, session);

        // Stage 2.3.3 — canonical identity, unless the runner reports a
        // distinct definition id
        var testDefinition = string.IsNullOrWhiteSpace(testDefinitionOverride)
            ? material.TestIdentity.ToFullString()
            : testDefinitionOverride.Trim();

        return new FailureInstance
        {
            InstanceId = instanceId,
            Signature = derivation.Signature,
            FailureId = derivation.FailureId,
            Session = session,
            Material = material,
            TestDefinitionId = testDefinition,
            SourceArtifact = sourceArtifact,
            OccurredAtUtc = occurredAtUtc
        };
    }
}