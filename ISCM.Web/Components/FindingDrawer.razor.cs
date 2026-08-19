using System.Diagnostics;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Web.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Microsoft.Win32;

namespace ISCM.Web.Components;

// Code-behind for the FindingDrawer glass modal (step 28 rework).
// 5-button action model: PS / Graphical / Undo / Rescan / Ignore.
// When no panel is open, the default "What & Why" description is shown.
public partial class FindingDrawer
{
    private const string TabOverview = "overview";
    private const string TabSubs = "subs";
    private const string TabSource = "source";

    private const string PNone = "";
    private const string PPs = "ps";
    private const string PGraph = "graph";
    private const string PUndo = "undo";
    private const string PRescan = "rescan";
    private const string PIgnore = "ignore";

    [Parameter] public Finding? SelectedFinding { get; set; }
    [Parameter] public SubCheck? InitialSubCheck { get; set; }
    [Parameter] public EventCallback Close { get; set; }

    [Inject] private ScanStateService StateService { get; set; } = default!;
    [Inject] private IJSRuntime JS { get; set; } = default!;

    private string ActiveTab = TabOverview;
    private string OpenPanel = PNone;
    private SubCheck? SelectedSubCheck;
    private Finding? _lastFinding;
    private bool ShowNavGuide;
    private bool ShowRegAlt;
    private string _undoNote = "";
    private string _rescanNote = "";

    protected override void OnParametersSet()
    {
        if (!ReferenceEquals(_lastFinding, SelectedFinding))
        {
            _lastFinding = SelectedFinding;
            ResetAll();
            SelectedSubCheck = InitialSubCheck;
        }
    }

    private void ResetAll()
    {
        SelectedSubCheck = null;
        OpenPanel = PNone;
        ShowNavGuide = false;
        ShowRegAlt = false;
        _undoNote = "";
        _rescanNote = "";
        ActiveTab = TabOverview;
    }

    private static IReadOnlyList<SubCheck> SubsFor(Finding f) =>
        f.SubChecks != null && f.SubChecks.Count > 0 ? f.SubChecks : GuidanceCatalog.Get(f.CheckId);

    private void SetTab(string tab) { ActiveTab = tab; OpenPanel = PNone; }

    private void OnModalKeyDown(KeyboardEventArgs e)
    { if (e.Key == "Escape") { _ = CloseDrawer(); } }

    private async Task CloseDrawer()
    { ResetAll(); await Close.InvokeAsync(); }

    // Toggle one of the 5 panels; closing returns to the default description.
    private void TogglePanel(string panel)
    {
        if (OpenPanel == panel) { OpenPanel = PNone; return; }
        OpenPanel = panel;
        ShowNavGuide = false; ShowRegAlt = false;
        if (panel == PUndo) EvaluateUndo();
        if (panel == PRescan) _ = EvaluateRescan();
    }

    private string DefaultDescription()
    {
        if (SelectedSubCheck != null)
            return $"{SelectedSubCheck.WhatItDoes} {SelectedSubCheck.Recommendation}";
        if (SelectedFinding != null)
            return $"{SelectedFinding.Description} {SelectedFinding.Recommendation}";
        return "";
    }

    // ⚡ PowerShell 3-line guide (with fallbacks)
    private string PsCheck() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.CheckCurrentCli) ? SelectedSubCheck!.CheckCurrentCli
        : SelectedSubCheck != null && SelectedSubCheck.HasRegistryPath ? $"reg query \"{SelectedSubCheck.RegistryPath}\""
        : SelectedFinding != null ? GetSourceCommand(SelectedFinding) : "";

    private string PsApply() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.CliCommand) ? SelectedSubCheck!.CliCommand
        : SelectedFinding != null ? GetUndoCliCommand(SelectedFinding) : "";

    private string PsVerify() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.VerifyCli) ? SelectedSubCheck!.VerifyCli
        : !string.IsNullOrEmpty(SelectedSubCheck?.Verification) ? SelectedSubCheck!.Verification
        : PsCheck();

    private string PsValueMap() => SelectedSubCheck?.ValueMap ?? "";
    private string PsTokens() => SelectedSubCheck?.CliTokens ?? "";

    // 🖱️ Graphical fix
    private string GraphTool() => SelectedSubCheck?.ConsoleTool ?? GetTools(SelectedFinding).FirstOrDefault() ?? "gpedit.msc";
    private string GraphPath() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.GraphicalPathFull) ? SelectedSubCheck!.GraphicalPathFull
        : SelectedSubCheck != null ? $"{SelectedSubCheck.YouAreHere} → {SelectedSubCheck.GoTo}"
        : SelectedFinding != null ? GetGraphicalPath(SelectedFinding) : "";

    private string GraphSteps() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.GraphicalSteps) ? SelectedSubCheck!.GraphicalSteps
        : SelectedFinding != null ? GetGraphicalPath(SelectedFinding) : "";

    private void OpenTool()
    {
        var tool = GraphTool();
        try
        {
            Process.Start(new ProcessStartInfo(tool) { UseShellExecute = true });
            StateService.LogAction($"Tool opened: {tool}");
        }
        catch (Exception ex) { StateService.LogAction($"Failed to open {tool}: {ex.Message}"); }
        ShowNavGuide = true;
    }

    // Launch an elevated PowerShell window for manual execution.
    private void OpenPowerShell()
    {
        try
        {
            Process.Start(new ProcessStartInfo("powershell.exe") { UseShellExecute = true, Verb = "runas" });
            StateService.LogAction("PowerShell opened (elevated).");
        }
        catch (Exception ex) { StateService.LogAction($"Failed to open PowerShell: {ex.Message}"); }
    }

    // ↶ Undo: check whether the item changed, then guide the reverse.
    private void EvaluateUndo()
    {
        var f = SelectedFinding;
        if (f == null) { _undoNote = "No finding selected."; return; }
        _undoNote = f.Status == CheckStatus.Pass
            ? "✅ This item WAS changed/hardened. Use the reverse guide below to restore the original state."
            : $"ℹ️ No change detected (current: {f.CurrentValue}). Nothing to undo yet.";
    }

    private string UndoCli() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.UndoCli) ? SelectedSubCheck!.UndoCli
        : SelectedFinding != null ? GetUndoCliCommand(SelectedFinding) : "";

    // 🔄 Rescan: fresh message on every click.
    private async Task EvaluateRescan()
    {
        if (SelectedFinding == null) { _rescanNote = "No finding selected."; return; }
        var scan = StateService.CurrentScanResult;
        var old = scan?.Findings.FirstOrDefault(x => x.CheckId == SelectedFinding.CheckId);
        var oldStatus = old?.Status; var oldValue = old?.CurrentValue;

        await StateService.RescanSingleCheckAsync(SelectedFinding.CheckId);

        var neu = StateService.CurrentScanResult?.Findings.FirstOrDefault(x => x.CheckId == SelectedFinding.CheckId);
        if (neu == null) _rescanNote = "⚠️ Finding not found after rescan.";
        else if (neu.Status == oldStatus && neu.CurrentValue == oldValue)
            _rescanNote = $"⚠️ No change — still {neu.CurrentValue} ({neu.Status}). Apply the fix first, then rescan.";
        else
            _rescanNote = $"✅ Change detected: {oldValue} ({oldStatus}) → {neu.CurrentValue} ({neu.Status}).";
    }

    private int BulkReadyCount => StateService.CurrentScanResult?.Findings.Count(f => f.Status == CheckStatus.Fail) ?? 0;

    private async Task BulkRescan()
    {
        if (StateService.CurrentScanResult == null) return;
        var n = BulkReadyCount;
        foreach (var f in StateService.CurrentScanResult.Findings.Where(x => x.Status == CheckStatus.Fail).ToList())
            await StateService.RescanSingleCheckAsync(f.CheckId);
        _rescanNote = $"✅ Bulk rescan finished for {n} failed items.";
    }

    // 🚫 Ignore consequence + confirm
    private string IgnoreConsequence() =>
        !string.IsNullOrEmpty(SelectedSubCheck?.IgnoreConsequence) ? SelectedSubCheck!.IgnoreConsequence
        : "Ignoring this finding leaves the current risk unaddressed. It moves to the Ignored list and is excluded from compliance scoring.";

    private void ConfirmIgnore()
    {
        if (SelectedFinding == null) return;
        if (SelectedFinding.IsSuppressed) { SelectedFinding.Undo(); StateService.LogAction($"Undid suppression: {SelectedFinding.CheckId}"); }
        else { SelectedFinding.Ignore(); StateService.LogAction($"Ignored: {SelectedFinding.CheckId}"); }
        OpenPanel = PNone;
    }

    private void OpenSubFromModal(SubCheck sc)
    { SelectedSubCheck = sc; OpenPanel = PNone; ShowNavGuide = false; ShowRegAlt = false; ActiveTab = TabOverview; }

    private void BackToSubList()
    { SelectedSubCheck = null; OpenPanel = PNone; ActiveTab = TabSubs; }

    private void ShowRegistryAlternative() { ShowRegAlt = true; ShowNavGuide = false; }

    private async Task CopyText(string text) => await CopyToClipboard(text);

    private async Task CopyToClipboard(string text)
    { try { await JS.InvokeVoidAsync("navigator.clipboard.writeText", text); } catch { } }

    private IEnumerable<string> GetTools(Finding? finding)
    {
        if (finding is null) return Array.Empty<string>();
        var tools = finding.FixTools.Count > 0 ? finding.FixTools : new[] { GetFixMethod(finding.CheckId) };
        return tools.Where(t => !t.Contains("powershell", StringComparison.OrdinalIgnoreCase));
    }

    private string GetFixMethod(string checkId)
    {
        if (checkId.StartsWith("FW") || checkId.StartsWith("SMB")) return "powershell.exe";
        if (checkId.StartsWith("GUEST") || checkId.StartsWith("ADM")) return "net.exe";
        if (checkId.StartsWith("PWD") || checkId.StartsWith("AUD")) return "secpol.msc";
        return "regedit.exe";
    }

    private static string GetRiskClass(int score)
        => score >= 80 ? "risk-high" : score >= 50 ? "risk-mid" : "risk-low";

    private static string GetSourceType(Finding f)
    {
        if (!string.IsNullOrEmpty(f.SourceType)) return f.SourceType;
        if (f.CheckId.StartsWith("PWD") || f.CheckId.StartsWith("AUD")) return "secedit";
        if (f.CheckId.StartsWith("GUEST") || f.CheckId.StartsWith("ADM")) return "net.exe";
        return "RegistryReader";
    }

    private static string GetSourceCommand(Finding f)
    {
        if (!string.IsNullOrEmpty(f.SourceCommand)) return f.SourceCommand;
        if (f.CheckId.StartsWith("PWD") || f.CheckId.StartsWith("AUD")) return "secedit /export /cfg output.txt";
        if (f.CheckId.StartsWith("GUEST") || f.CheckId.StartsWith("ADM")) return "net user";
        return string.IsNullOrEmpty(f.RegistryPath) ? "reg query HKLM" : $"reg query {f.RegistryPath}";
    }

    private string GetGraphicalPath(Finding finding)
    {
        if (finding.CheckId.StartsWith("FW")) return "wf.msc → Windows Defender Firewall with Advanced Security → Properties → profile state On / Inbound Block";
        if (finding.CheckId.StartsWith("SMB")) return "Control Panel → Programs → Turn Windows features on/off → uncheck SMB 1.0/CIFS File Sharing Support";
        if (finding.CheckId.StartsWith("RDP")) return "System Properties → Remote → Allow connections only with NLA";
        if (finding.CheckId.StartsWith("USB")) return "gpedit.msc → Computer Configuration → Administrative Templates → System → Removable Storage Access";
        if (finding.CheckId.StartsWith("DEF")) return "Windows Security → Virus & threat protection → Manage settings → Real-time protection On";
        if (finding.CheckId.StartsWith("UAC")) return "Control Panel → User Accounts → Change UAC settings → raise slider";
        if (finding.CheckId.StartsWith("ARD")) return "gpedit.msc → Windows Components → AutoPlay Policies → Turn off AutoPlay = Enabled (All drives)";
        if (finding.CheckId.StartsWith("GUEST")) return "compmgmt.msc → Local Users and Groups → Users → Guest → Properties → Account is disabled";
        if (finding.CheckId.StartsWith("ADM")) return "compmgmt.msc → Local Users and Groups → Groups → Administrators → review members";
        if (finding.CheckId.StartsWith("ALG")) return "netplwiz → uncheck 'Users must enter a user name and password'";
        if (finding.CheckId.StartsWith("PWD")) return "secpol.msc → Account Policies → Password Policy → Minimum password length = 14";
        if (finding.CheckId.StartsWith("WUP")) return "gpedit.msc → Windows Components → Windows Update → Configure Automatic Updates = Enabled (4)";
        if (finding.CheckId.StartsWith("LM")) return "secpol.msc → Security Options → LAN Manager authentication level = NTLMv2 only";
        if (finding.CheckId.StartsWith("EVL")) return "eventvwr.msc → Windows Logs → right-click log → Properties → Maximum log size (KB)";
        return finding.Recommendation;
    }

    private static string GetUndoCliCommand(Finding finding)
    {
        if (finding.CheckId.StartsWith("FW")) return "Set-NetFirewallProfile -Profile Domain -Enabled True";
        if (finding.CheckId.StartsWith("SMB")) return "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force";
        if (finding.CheckId.StartsWith("RDP")) return "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1";
        if (finding.CheckId.StartsWith("USB")) return "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 4";
        if (finding.CheckId.StartsWith("DEF")) return "Set-MpPreference -DisableRealtimeMonitoring $false";
        if (finding.CheckId.StartsWith("UAC")) return "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1";
        if (finding.CheckId.StartsWith("ARD")) return "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255";
        if (finding.CheckId.StartsWith("GUEST")) return "net user Guest /active:no";
        if (finding.CheckId.StartsWith("ADM")) return "# Review and remove unnecessary admin accounts via lusrmgr.msc";
        if (finding.CheckId.StartsWith("ALG")) return "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0";
        if (finding.CheckId.StartsWith("PWD")) return "net accounts /minpwlen:14";
        if (finding.CheckId.StartsWith("WUP")) return "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -Value 1";
        if (finding.CheckId.StartsWith("LM")) return "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5";
        return "# Use " + (finding.FixTools.FirstOrDefault() ?? "relevant tool") + " to set to " + finding.ExpectedValue;
    }
}