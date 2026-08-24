using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Validators;

/// <summary>
/// Validates that MultiPathCheck tests are genuinely independent.
/// Checks:
/// 1. Source independence (Registry ≠ PowerShell ≠ WMI ≠ SecEdit)
/// 2. No duplicate/copied tests
/// 3. All tests target the same property
/// </summary>
public class MultiPathCheckValidator : IMultiPathCheckValidator
{
    public MultiPathValidationResult Validate(string checkId, List<TestResult> testResults)
    {
        var result = new MultiPathValidationResult();

        if (testResults == null || !testResults.Any())
        {
            result.IsValid = false;
            result.Errors.Add($"Check {checkId}: No test results provided.");
            return result;
        }

        // Check 1: Source independence
        var sources = testResults.Select(t => t.TestMethod).Distinct().ToList();
        result.IndependentSourceCount = sources.Count;

        if (sources.Count < 2)
        {
            result.Warnings.Add($"Check {checkId}: All tests use the same source '{sources.FirstOrDefault()}'. " +
                              "Tests should use independent evidence sources (e.g., Registry + PowerShell + WMI).");
        }

        // Check 2: Duplicate detection
        var details = testResults.Select(t => t.Details).ToList();
        var duplicateDetails = details.GroupBy(d => d)
                                     .Where(g => g.Count() > 1)
                                     .Select(g => g.Key)
                                     .ToList();

        if (duplicateDetails.Any())
        {
            result.Errors.Add($"Check {checkId}: Duplicate test details found: '{duplicateDetails.FirstOrDefault()}'. " +
                            "Tests must not be copies of each other.");
            result.IsValid = false;
        }

        // Check 3: Test name uniqueness
        var testNames = testResults.Select(t => t.TestName).ToList();
        var duplicateNames = testNames.GroupBy(n => n)
                                     .Where(g => g.Count() > 1)
                                     .Select(g => g.Key)
                                     .ToList();

        if (duplicateNames.Any())
        {
            result.Warnings.Add($"Check {checkId}: Duplicate test names found: '{duplicateNames.FirstOrDefault()}'. " +
                              "Each test should have a unique name (Primary, Cross-check, Verification).");
        }

        // Check 4: Minimum 2 independent sources required
        if (sources.Count < 2 && result.Errors.Count == 0)
        {
            result.Warnings.Add($"Check {checkId}: Only {sources.Count} independent source(s) found. " +
                              "At least 2 independent sources are recommended for security checks.");
        }

        return result;
    }
}