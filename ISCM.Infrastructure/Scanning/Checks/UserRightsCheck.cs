using ISCM.Application.Interfaces;
using ISCM.Application.Parsers;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace ISCM.Infrastructure.Scanning.Checks;

/// <summary>
/// Phase 10.9: User Rights Assignment Check (Collector-only pattern).
/// 
/// SubControls (9 migrated, all Collection with SetMembership):
///   - URA-001.1: SeNetworkLogonRight → Collection (Administrators, Remote Desktop Users)
///   - URA-001.2: SeDenyNetworkLogonRight → Collection (Guests, Local account)
///   - URA-001.3: SeDenyBatchLogonRight → Collection (Guests)
///   - URA-001.4: SeDenyServiceLogonRight → Collection (Guests)
///   - URA-001.5: SeDenyInteractiveLogonRight → Collection (Guests)
///   - URA-001.6: SeDenyRemoteInteractiveLogonRight → Collection (Guests, Local account)
///   - URA-001.7: SeRemoteInteractiveLogonRight → Collection (Administrators, Remote Desktop Users)
///   - URA-001.8: SeDebugPrivilege → Collection (Administrators)
///   - URA-001.9: SeTakeOwnershipPrivilege → Collection (Administrators)
/// 
/// Phase 10.9 fix: Use EvidenceValue constructor directly (no FromCollection factory).
/// </summary>
[SupportedOSPlatform("windows")]
public class UserRightsCheck : BaseHardeningCheck
{
    private readonly IEvidenceParser _registryParser;

    // Mapping: SubControlId → (PrivilegeName, RawOutput key)
    private static readonly Dictionary<string, string> SubControlToPrivilege = new()
    {
        { "URA-001.1", "SeNetworkLogonRight" },
        { "URA-001.2", "SeDenyNetworkLogonRight" },
        { "URA-001.3", "SeDenyBatchLogonRight" },
        { "URA-001.4", "SeDenyServiceLogonRight" },
        { "URA-001.5", "SeDenyInteractiveLogonRight" },
        { "URA-001.6", "SeDenyRemoteInteractiveLogonRight" },
        { "URA-001.7", "SeRemoteInteractiveLogonRight" },
        { "URA-001.8", "SeDebugPrivilege" },
        { "URA-001.9", "SeTakeOwnershipPrivilege" }
    };

    // Well-known SIDs to friendly names
    private static readonly Dictionary<string, string> SidToName = new(StringComparer.OrdinalIgnoreCase)
    {
        { "*S-1-5-32-544", "Administrators" },
        { "*S-1-5-32-546", "Guests" },
        { "*S-1-5-32-555", "Remote Desktop Users" },
        { "*S-1-11-0", "Local account" },
        { "*S-1-5-11", "Authenticated Users" },
        { "*S-1-5-32-545", "Users" },
        { "*S-1-5-18", "SYSTEM" },
        { "*S-1-5-19", "LOCAL SERVICE" },
        { "*S-1-5-20", "NETWORK SERVICE" }
    };

    public override string CheckId => "URA-001";
    public override string Name => "User Rights Assignment";
    public override CheckCategory Category => CheckCategory.Account;
    public override CheckSeverity Severity => CheckSeverity.Medium;

    public UserRightsCheck()
    {
        _registryParser = new RegistryParser();
    }

    public override async Task<List<Evidence>> CollectEvidenceAsync()
    {
        var evidenceList = new List<Evidence>();

        // Run secedit once for all SubControls
        var seceditOutput = await RunSeceditExportAsync();
        var privilegeMap = ParsePrivilegeRights(seceditOutput);

        foreach (var kvp in SubControlToPrivilege)
        {
            var subControlId = kvp.Key;
            var privilegeName = kvp.Value;

            try
            {
                var startTime = DateTime.UtcNow;

                // Extract groups for this privilege
                var groups = new List<object>();
                if (privilegeMap.TryGetValue(privilegeName, out var sids) && sids != null)
                {
                    foreach (var sid in sids)
                    {
                        var friendlyName = SidToName.TryGetValue(sid, out var name) ? name : sid;
                        groups.Add(friendlyName);
                    }
                }

                // Phase 10.9 fix: Use constructor directly, not FromCollection
                var rawString = groups.Count > 0
                    ? string.Join(", ", groups.Cast<string>())
                    : "(empty)";
                var typedValue = new EvidenceValue(
                    groups,
                    EvidenceValueType.Collection,
                    rawString: rawString);

                var parsedValue = _registryParser.Parse(seceditOutput, "Secedit");

                evidenceList.Add(new Evidence
                {
                    EvidenceId = $"{CheckId}-{subControlId}",
                    SubControlId = subControlId,
                    SourceType = EvidenceSourceType.Other,
                    SourceName = $"secedit /areas USER_RIGHTS",
                    AcquisitionCommand = "secedit /export /cfg C:\\temp\\ura.inf /areas USER_RIGHTS",
                    RawOutput = privilegeMap.ContainsKey(privilegeName)
                        ? $"{privilegeName} = {string.Join(",", sids ?? new List<string>())}"
                        : $"{privilegeName} not configured",
                    ParsedValue = parsedValue,
                    TypedValue = typedValue,
                    Evaluation = CheckStatus.NotScanned,
                    CollectedAtUtc = DateTime.UtcNow,
                    CollectionDurationMs = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                });
            }
            catch (Exception ex)
            {
                evidenceList.Add(CreateErrorEvidence(subControlId, ex));
            }
        }

        return evidenceList;
    }

    /// <summary>
    /// Parses secedit output to extract [Privilege Rights] section.
    /// Returns dictionary: privilege name → list of SIDs.
    /// </summary>
    private static Dictionary<string, List<string>> ParsePrivilegeRights(string seceditOutput)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(seceditOutput))
            return result;

        bool inPrivilegeSection = false;

        foreach (var rawLine in seceditOutput.Split('\n'))
        {
            var line = rawLine.Trim();

            // Detect section boundaries
            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                inPrivilegeSection = line.Equals("[Privilege Rights]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (!inPrivilegeSection)
                continue;

            // Skip empty lines and comments
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";", StringComparison.Ordinal))
                continue;

            // Parse: PrivilegeName = *S-1-5-32-544,*S-1-5-32-555
            var parts = line.Split('=', 2);
            if (parts.Length != 2)
                continue;

            var privilegeName = parts[0].Trim();
            var sidList = parts[1].Trim()
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .ToList();

            result[privilegeName] = sidList;
        }

        return result;
    }

    /// <summary>
    /// Runs secedit /export to get USER_RIGHTS configuration.
    /// </summary>
    private static async Task<string> RunSeceditExportAsync()
    {
        try
        {
            if (!Directory.Exists(@"C:\temp"))
            {
                Directory.CreateDirectory(@"C:\temp");
            }

            var tempFile = Path.Combine(@"C:\temp", $"ura_{Guid.NewGuid():N}.inf");

            var psi = new ProcessStartInfo("secedit.exe", $"/export /cfg \"{tempFile}\" /areas USER_RIGHTS")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
                return string.Empty;

            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (File.Exists(tempFile))
            {
                var content = await File.ReadAllTextAsync(tempFile);
                try { File.Delete(tempFile); } catch { }
                return content;
            }

            return string.Empty;
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }

    private static Evidence CreateErrorEvidence(string subControlId, Exception ex)
    {
        // Phase 10.9 fix: Use constructor directly for empty collection
        var emptyCollection = new EvidenceValue(
            new List<object>(),
            EvidenceValueType.Collection,
            rawString: "(empty)");

        return new Evidence
        {
            EvidenceId = $"URA-001-{subControlId}",
            SubControlId = subControlId,
            SourceType = EvidenceSourceType.Other,
            SourceName = "secedit",
            RawOutput = ex.Message,
            TypedValue = emptyCollection,
            Evaluation = CheckStatus.Error,
            Error = ex.Message,
            CollectedAtUtc = DateTime.UtcNow
        };
    }
}