using System.Security.Cryptography;
using System.Text;
using ISCM.Domain.Entities;

namespace ISCM.Web.Services;

// ── انواع تصمیم کنترلر ──
public enum GateKind
{
    Locked,         // هنوز اسکنی وجود ندارد
    FirstAllowed,   // اولین گزارش مجاز است
    Blocked,        // تغییری tespit نشده → مسدود
    ChangeAllowed   // تغییر تشخیص داده شد → مجاز
}

public sealed class GateDecision
{
    public GateKind Kind { get; init; }
    public string Message { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;

    public static GateDecision Locked(string message) => new() { Kind = GateKind.Locked, Message = message };
    public static GateDecision FirstAllowed(string signature) => new() { Kind = GateKind.FirstAllowed, Signature = signature };
    public static GateDecision Blocked(string message) => new() { Kind = GateKind.Blocked, Message = message };
    public static GateDecision ChangeAllowed(string signature) => new() { Kind = GateKind.ChangeAllowed, Signature = signature };
}

// ── رکورد بایگانی (Ledger) هر گزارش تولیدشده ──
public sealed class ReportLedgerEntry
{
    public int Seq { get; set; }
    public string ReportType { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string StateSignature { get; set; } = string.Empty;
    public DateTimeOffset GeneratedAt { get; set; }
}

// EDIT (گام ۲۵): کنترلر Report Gate — جلوگیری از خروجی تکراری بدون تغییر پیکربندی
public class ReportGateService
{
    private readonly List<ReportLedgerEntry> _ledger = new();
    private string? _lastSignature;

    public IReadOnlyList<ReportLedgerEntry> Ledger => _ledger.AsReadOnly();
    public bool HasFirstReport => _lastSignature != null;
    public int LastSequence => _ledger.Count;

    // ── امضای وضعیت: SHA-256 روی Hostname + لیست مرتب‌شدهٔ CheckId|Status|CurrentValue ──
    public string ComputeStateSignature(ScanResult scan)
    {
        var sb = new StringBuilder();
        sb.Append(scan.Hostname ?? "Unknown").Append('|');
        foreach (var f in scan.Findings.OrderBy(x => x.CheckId))
        {
            sb.Append(f.CheckId).Append('|').Append(f.Status).Append('|').Append(f.CurrentValue).Append(';');
        }

        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(hash);
    }

    // ── ارزیابی برای گزارش Current State ──
    public GateDecision EvaluateCurrentState(ScanResult? scan)
    {
        if (scan == null)
            return GateDecision.Locked(
                "No scan available. Run a scan from the Dashboard before generating a Current State report.");

        var signature = ComputeStateSignature(scan);

        // قانون ۱: بعد از اولین اسکن، اولین گزارش همیشه مجاز است
        if (!HasFirstReport)
            return GateDecision.FirstAllowed(signature);

        // قانون ۲: بدون تغییر → مسدود با هشدار حرفه‌ای
        if (signature == _lastSignature)
            return GateDecision.Blocked(
                $"No configuration change detected since report R-{LastSequence:D3}. " +
                "Apply hardening changes and run a new scan before generating another Current State report.");

        // قانون ۳: تغییر تشخیص داده شد → مجاز
        return GateDecision.ChangeAllowed(signature);
    }

    // ── ثبت هر گزارش (هر نوع و هر فرمت) — چک تغییر پس از اولین گزارش فعال می‌شود ──
    public ReportLedgerEntry RecordReport(ScanResult scan, string reportType, string format, string filePath)
    {
        var entry = new ReportLedgerEntry
        {
            Seq = _ledger.Count + 1,
            ReportType = reportType,
            Format = format,
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            StateSignature = ComputeStateSignature(scan),
            GeneratedAt = DateTimeOffset.Now
        };

        _ledger.Add(entry);
        _lastSignature = entry.StateSignature;
        return entry;
    }

    // ── ساخت نام فایل هوشمند ──
    // اولین گزارش Current State:  DefenDoor_CurrentState_FIRST_{host}_{ts}.{ext}
    // گزارش‌های بعدی:              DefenDoor_CurrentState_R{seq}_{host}_{ts}.{ext}
    public string BuildFileName(ScanResult scan, string reportType, string extension)
    {
        var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var host = (scan.Hostname ?? "Unknown").Replace(" ", "_").Replace("/", "_");

        var typeTag = reportType switch
        {
            "current" => HasFirstReport ? $"CurrentState_R{LastSequence + 1:D3}" : "CurrentState_FIRST",
            "beforeafter" => "BeforeAfter",
            "remediation" => "Remediation",
            _ => "Report"
        };

        return $"DefenDoor_{typeTag}_{host}_{ts}.{extension}";
    }
}