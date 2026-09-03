using System;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities;

/// <summary>
/// Complete provenance information for evidence acquisition.
/// Tracks exactly how, when, and where evidence was collected.
/// </summary>
public class EvidenceProvenance
{
    public string AcquisitionMechanism { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
    public string? Arguments { get; set; }
    public string? RawOutput { get; set; }
    public string? ParsedValue { get; set; }
    public string? NormalizedValue { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string MachineIdentity { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;

    public EvidenceProvenance() { }

    public EvidenceProvenance(
        string acquisitionMechanism,
        string source,
        string command,
        string machineIdentity)
    {
        AcquisitionMechanism = acquisitionMechanism;
        Source = source;
        Command = command;
        MachineIdentity = machineIdentity;
        TimestampUtc = DateTime.UtcNow;
    }

    public void ComputeFingerprint()
    {
        var content = $"{AcquisitionMechanism}|{Source}|{Command}|{NormalizedValue}|{TimestampUtc:O}|{MachineIdentity}";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        Fingerprint = Convert.ToBase64String(sha256.ComputeHash(bytes));
    }
}