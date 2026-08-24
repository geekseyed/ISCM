using ISCM.Domain.Entities;
using System.Collections.Generic;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Validates that the three tests in a MultiPathCheck are genuinely independent
/// and target the same security property.
/// </summary>
public interface IMultiPathCheckValidator
{
    /// <summary>
    /// Validates the test results from a MultiPathCheck.
    /// </summary>
    /// <param name="checkId">The CheckId being validated.</param>
    /// <param name="testResults">The list of TestResult objects.</param>
    /// <returns>ValidationResult with any issues found.</returns>
    MultiPathValidationResult Validate(string checkId, List<TestResult> testResults);
}

/// <summary>
/// Result of MultiPathCheck validation.
/// </summary>
public class MultiPathValidationResult
{
    public bool IsValid { get; set; } = true;
    public List<string> Warnings { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public int IndependentSourceCount { get; set; }
}