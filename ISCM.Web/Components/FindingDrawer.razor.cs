using System.Diagnostics;
using ISCM.Domain.Entities;
using ISCM.Domain.Enums;
using ISCM.Web.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace ISCM.Web.Components;

// EDIT (گام ۲۶-بخش ۲): بخش کد Drawer — پنل‌های جدید ⚡ / 🧭 /  + پیام Rescan
public partial class FindingDrawer
{
    [Parameter] public Finding? SelectedFinding { get; set; }
    [Parameter] public SubCheck? InitialSubCheck { get; set; }
    [Parameter] public EventCallback Close { get; set; }

    [Inject] private ScanStateService StateService { get; set; } = default!;
    [Inject] private IJSRuntime JS { get; set; } = default!;

    private ToolPathInfo? ActiveToolPanel;
    private bool ShowUndoPanel;
    private SubCheck? SelectedSubCheck;
    private Finding? _lastFinding;

    // پنل‌های جدید بخش ۲
    private bool ShowPsPanel;
    private bool ShowNavGuide;
    private bool ShowRegAlt;
    private string? RescanMessage;

    protected override void OnParametersSet()
    {
        if (!ReferenceEquals(_lastFinding, SelectedFinding))
        {
            _lastFinding = SelectedFinding;
            ResetPanels();
            SelectedSubCheck = InitialSubCheck;
        }
    }

    private void ResetPanels()
    {
        SelectedSubCheck = null;
        ActiveToolPanel = null;
        ShowUndoPanel = false;
        ShowPsPanel = false;
        ShowNavGuide = false;
        ShowRegAlt = false;
        RescanMessage = null;
    }

    private sealed class ToolPathInfo
    {
        public string Tool { get; set; } = "";
        public string NavigationPath { get; set; } = "";
    }

    private async Task CloseDrawer()
    {
        ResetPanels();
        await Close.InvokeAsync();
    }

    // ── ناوبری زیرمجموعه‌ها ──
    private void OpenSubCheck(SubCheck sc)
    {
        SelectedSubCheck = sc;
        ShowNavGuide = false;
        ShowRegAlt = false;
    }

    private void BackToSubList() => SelectedSubCheck = null;

    // ──  PowerShell Prompt & Guide (نوار بالا) ──
    private string CurrentCli =>
        SelectedSubCheck != null ? SelectedSubCheck.CliCommand
        : SelectedFinding != null ? GetUndoCliCommand(SelectedFinding) : "";

    private string CurrentRecommendation =>
        SelectedSubCheck?.Recommendation ?? "Run the prompt below in an elevated PowerShell, then verify the result.";

    private string CurrentVerification =>
        SelectedSubCheck?.Verification ?? "After running, click Rescan and confirm the status flips to Pass.";

    private void TogglePsPanel() => ShowPsPanel = !ShowPsPanel;

    private async Task CopyCurrentCli() => await CopyToClipboard(CurrentCli);

    // ── 🧭 دکمهٔ مقصد: باز کردن کنسول + راهنمای نورانی ──
    private void OpenConsoleWithGuide()
    {
        if (SelectedSubCheck == null) return;
        try
        {
            if (!string.IsNullOrEmpty(SelectedSubCheck.ConsoleTool))
            {
                Process.Start(new ProcessStartInfo(SelectedSubCheck.ConsoleTool) { UseShellExecute = true });
                StateService.LogAction($"Console opened: {SelectedSubCheck.ConsoleTool} for {SelectedSubCheck.Id}");
            }
        }
        catch (Exception ex)
        {
            StateService.LogAction($"Failed to open console: {ex.Message}");
        }
        ShowNavGuide = true;
        ShowRegAlt = false;
    }

    // ── 🎯 جایگزین رجیستری (بدون باز کردن regedit) ──
    private void ShowRegistryAlternative()
    {
        ShowRegAlt = true;
        ShowNavGuide = false;
    }

    // ── 🔄 Rescan با پیام درون‌خطی ──
    private async Task RescanFinding()
    {
        if (SelectedFinding == null) return;
        var scan = StateService.CurrentScanResult;
        var old = scan?.Findings.FirstOrDefault(x => x.CheckId == SelectedFinding.CheckId);
        var oldStatus = old?.Status;
        var oldValue = old?.CurrentValue;

        await StateService.RescanSingleCheckAsync(SelectedFinding.CheckId);

        var neu = StateService.CurrentScanResult?.Findings.FirstOrDefault(x => x.CheckId == SelectedFinding.CheckId);
        if (neu == null)
        {
            RescanMessage = "⚠️ Finding not found after rescan.";
        }
        else if (neu.Status == oldStatus && neu.CurrentValue == oldValue)
        {
            RescanMessage = $"ℹ️ No change detected — still {neu.CurrentValue} ({neu.Status}). Apply the fix via the ⚡ prompt, then rescan.";
        }
        else
        {
            RescanMessage = $"✅ Change detected: {oldValue} ({oldStatus}) → {neu.CurrentValue} ({neu.Status}).";
        }
    }

    // ── اکشن‌های سطح پدر ──
    private void ShowPolicyToolPath(Finding finding, string tool)
    {
        ShowUndoPanel = false;
        ActiveToolPanel = new ToolPathInfo { Tool = tool, NavigationPath = BuildNavigationPath(finding, tool) };
    }

    private void ToggleUndoPanel()
    {
        if (ShowUndoPanel) { ShowUndoPanel = false; }
        else { ActiveToolPanel = null; ShowUndoPanel = true; }
    }

    private void ToggleIgnore()
    {
        if (SelectedFinding == null) return;
        if (SelectedFinding.IsSuppressed)
        {
            SelectedFinding.Undo();
            StateService.LogAction($"User undid suppression: {SelectedFinding.CheckId}");
        }
        else
        {
            SelectedFinding.Ignore();
            StateService.LogAction($"User ignored: {SelectedFinding.CheckId}");
        }
    }

    private async Task CopySourceCommand()
    {
        if (SelectedFinding != null)
            await CopyToClipboard(GetSourceCommand(SelectedFinding));
    }

    private async Task CopyUndoCommand(Finding f) => await CopyToClipboard(GetUndoCliCommand(f));

    private async Task CopySubCli()
    {
        if (SelectedSubCheck != null)
            await CopyToClipboard(SelectedSubCheck.CliCommand);
    }

    private async Task CopyToClipboard(string text)
    {
        try { await JS.InvokeVoidAsync("navigator.clipboard.writeText", text); } catch { }
    }

    // EDIT (بخش ۲): powershell از نوار بالا حذف شد؛ دکمهٔ ⚡ جای آن را گرفت
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

    private string BuildNavigationPath(Finding finding, string tool)
    {
        if (tool == "secpol.msc") return "Open secpol.msc → Account Policies / Local Policies → Security Options → Locate setting";
        if (tool == "gpedit.msc") return "Open gpedit.msc → Computer Configuration → Administrative Templates → Locate policy";
        if (tool == "wf.msc") return "Open wf.msc → Inbound Rules / Outbound Rules → Configure";
        if (tool == "regedit.exe") return "Open regedit.exe → Navigate to: " + (finding.RegistryPath ?? "HKLM");
        if (tool == "net.exe") return "Open CMD/PowerShell as Administrator → Run net user / net localgroup commands";
        if (tool == "lusrmgr.msc") return "Open lusrmgr.msc → Users → Double-click user → Modify settings";
        if (tool == "compmgmt.msc") return "Open compmgmt.msc → Local Users and Groups → Groups → Administrators";
        if (tool == "OptionalFeatures.exe") return "Open OptionalFeatures.exe → Locate feature → Uncheck → OK → Restart";
        return "Open " + tool + " → Navigate to relevant policy section";
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

    private static string GetGraphicalPath(Finding finding)
    {
        if (finding.CheckId.StartsWith("FW")) return "Control Panel → Windows Defender Firewall → Turn on for Domain";
        if (finding.CheckId.StartsWith("SMB")) return "Open wf.msc → Advanced Settings → Inbound Rules → Disable SMBv1 rules. Or: Control Panel → Programs → Turn Windows features on/off → uncheck SMB 1.0/CIFS.";
        if (finding.CheckId.StartsWith("RDP")) return "System Properties → Remote → Allow remote connections → Check NLA";
        if (finding.CheckId.StartsWith("USB")) return "Group Policy Editor → Computer Configuration → Administrative Templates → System → Removable Storage Access";
        if (finding.CheckId.StartsWith("DEF")) return "Windows Security → Virus & threat protection → Manage settings → Turn on Real-time";
        if (finding.CheckId.StartsWith("UAC")) return "Control Panel → User Accounts → Change UAC settings → Raise slider";
        if (finding.CheckId.StartsWith("ARD")) return "Group Policy Editor → Administrative Templates → Windows Components → AutoPlay Policies";
        if (finding.CheckId.StartsWith("GUEST")) return "Computer Management → Local Users and Groups → Users → Guest → Disable";
        if (finding.CheckId.StartsWith("ADM")) return "Computer Management → Local Users and Groups → Groups → Administrators → Review members";
        if (finding.CheckId.StartsWith("ALG")) return "netplwiz → Uncheck 'Users must enter a user name and password'";
        if (finding.CheckId.StartsWith("PWD")) return "Open secpol.msc → Account Policies → Password Policy → Minimum password length → Set to 14.";
        if (finding.CheckId.StartsWith("WUP")) return "Group Policy Editor → Windows Update → Configure Automatic Updates → Disabled";
        if (finding.CheckId.StartsWith("LM")) return "Local Security Policy → Security Options → LAN Manager authentication level = NTLMv2 only";
        return finding.Recommendation;
    }
}