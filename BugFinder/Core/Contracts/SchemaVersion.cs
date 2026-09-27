using System;
using System.Collections.Generic;
using System.Text.Json;

namespace ISCM.BugFinder.Core.Contracts;

/// <summary>
/// H-01.3: Schema &amp; Version Contract.
/// Single source of truth for persisted-artifact schema versioning
/// (audit KBF-00-010: no global schema/version policy existed).
///
/// BACKWARD COMPATIBILITY RULES (H-01.3.5):
///   - Same version: additive optional properties only; readers ignore
///     unknown properties (System.Text.Json default).
///   - Breaking change (rename/remove/restructure) => version bump +
///     a registered migrator for the previous version.
///
/// INCOMPATIBLE-VERSION REJECTION (H-01.3.6):
///   - Document newer than reader  => NewerThanReader (explicit).
///   - Document older, no migrator => RequiresMigration (explicit).
///   - Neither is EVER silently converted to an empty/default state
///     (anti-pattern from audit KBF-11-004: corruption became "no history").
///
/// MIGRATION POLICY (H-01.3.7):
///   - Migrators are registered per (Family, fromVersion) and transform
///     payload vN -> v(N+1); the reader applies the chain step by step
///     until the current version, reporting Status = Migrated.
/// </summary>
public static class CoreSchema
{
    /// <summary>
    /// Single source of truth for the current persisted-schema version.
    /// BaselineManifest.CurrentSchemaVersion derives from this constant.
    /// </summary>
    public const int CurrentVersion = 1;
}

/// <summary>Artifact families whose persisted payloads are versioned.</summary>
public enum SchemaFamily
{
    Evidence,             // H-01.3.2 — EvidencePackage and friends
    History,              // H-01.3.3 — FailureHistoryStore and friends
    InvestigationReport   // H-01.3.4 — terminal InvestigationReport
}

/// <summary>Explicit outcome of reading a persisted artifact.</summary>
public enum SchemaReadStatus
{
    Current,           // document version == reader version
    Migrated,          // older document, migrator chain applied
    RequiresMigration, // older document, no migrator registered (explicit)
    NewerThanReader,   // document version > reader version (explicit rejection)
    FamilyMismatch,    // envelope family != reader family
    Malformed          // not parseable / missing fields / payload mismatch
}

/// <summary>The physical persisted-envelope shape (payload kept opaque).</summary>
public sealed class SchemaEnvelope
{
    public int SchemaVersion { get; set; }
    public string Family { get; set; } = string.Empty;
    public JsonElement Payload { get; set; }
}

/// <summary>H-01.8 seed: typed read result with explicit status + diagnostics.</summary>
public sealed class SchemaReadResult<T>
{
    public SchemaReadStatus Status { get; init; }
    public T? Payload { get; init; }
    public int DocumentSchemaVersion { get; init; }
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    /// <summary>True only when the payload may be consumed downstream.</summary>
    public bool IsUsable =>
        Status is SchemaReadStatus.Current or SchemaReadStatus.Migrated;
}