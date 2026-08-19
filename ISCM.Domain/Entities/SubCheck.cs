namespace ISCM.Domain.Entities;

// Guidance model for a single sub-setting of a hardening check.
// Step 28: 3-line PowerShell guide, value map, undo, ignore-consequence,
// precise graphical path. Single namespace, single class (CS8954 fix).
public class SubCheck
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Expected { get; set; } = string.Empty;
    public string WhatItDoes { get; set; } = string.Empty;

    // Default "What & Why" description
    public string Recommendation { get; set; } = string.Empty;

    // PowerShell 3-line guide
    public string CheckCurrentCli { get; set; } = string.Empty;   // 1) read current state
    public string CliCommand { get; set; } = string.Empty;        // 2) apply change
    public string VerifyCli { get; set; } = string.Empty;         // 3) verify success
    public string Verification { get; set; } = string.Empty;      // human-readable verify text
    public string ValueMap { get; set; } = string.Empty;          // e.g. "1 = Enabled, 0 = Disabled"
    public string CliTokens { get; set; } = string.Empty;         // explanation of parameters

    // Graphical (GUI) remediation
    public string ConsoleTool { get; set; } = "";
    public string DestinationLabel { get; set; } = string.Empty;
    public string GraphicalPathFull { get; set; } = string.Empty;
    public string YouAreHere { get; set; } = string.Empty;
    public string GoTo { get; set; } = string.Empty;
    public string GraphicalSteps { get; set; } = string.Empty;
    public string ConsolePath { get; set; } = string.Empty;

    // Undo (reverse operation)
    public string UndoCli { get; set; } = string.Empty;

    // Ignore consequence
    public string IgnoreConsequence { get; set; } = string.Empty;

    // Registry
    public bool HasRegistryPath { get; set; }
    public string RegistryPath { get; set; } = "";
    public string AlternativeToRegistry { get; set; } = string.Empty;
}