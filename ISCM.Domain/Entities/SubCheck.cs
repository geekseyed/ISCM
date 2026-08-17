namespace ISCM.Domain.Entities;

// EDIT (گام ۲۶): زیرمجموعهٔ راهنما — هر Finding می‌تواند چند SubCheck با مسیریابی مستقیم داشته باشد
public class SubCheck
{
    public string Id { get; set; } = string.Empty;              // GUEST-001.1
    public string Title { get; set; } = string.Empty;           // Accounts: Guest account status
    public string Expected { get; set; } = string.Empty;        // Disabled
    public string WhatItDoes { get; set; } = string.Empty;      // توضیح PDF
    public string ConsolePath { get; set; } = string.Empty;     // breadcrumb مسیر GPO
    public string ConsoleTool { get; set; } = "secpol.msc";     // ابزار کنسول
    public string DestinationLabel { get; set; } = string.Empty; // نام مقصد نهایی برای دکمه
    public string? RegistryPath { get; set; }                   // برای Jump to Registry
    public string CliCommand { get; set; } = string.Empty;      // PowerShell اقدام
}