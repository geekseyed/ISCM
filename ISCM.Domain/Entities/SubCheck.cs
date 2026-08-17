namespace ISCM.Domain.Entities;

// EDIT (گام ۲۶): مدل راهنمای مقصد‌محور — توصیه → پرامپت → verifikasi + ناوبری نورانی
public class SubCheck
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Expected { get; set; } = string.Empty;
    public string WhatItDoes { get; set; } = string.Empty;
    public string ConsolePath { get; set; } = string.Empty;

    // ۱) دستور توصیه‌ای (چرا و چه چیزی)
    public string Recommendation { get; set; } = string.Empty;
    // ۲) پرامپت اجرایی (PowerShell)
    public string CliCommand { get; set; } = string.Empty;
    // ۳) بررسی موفقیت بعد از اجرا (کجا چک کنه)
    public string Verification { get; set; } = string.Empty;

    // ناوبری گرافیکی (🧭)
    public string ConsoleTool { get; set; } = "";
    public string DestinationLabel { get; set; } = string.Empty;
    public string YouAreHere { get; set; } = string.Empty;   // الان کجایی
    public string GoTo { get; set; } = string.Empty;         // کجا باید بری (نورانی)
    public string GraphicalSteps { get; set; } = string.Empty;

    // جایگزین رجیستری (🎯)
    public bool HasRegistryPath { get; set; }
    public string RegistryPath { get; set; } = "";
    public string AlternativeToRegistry { get; set; } = string.Empty;
}