using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

/// <summary>
/// Interface for checks that implement multiple real verification methods.
/// Each check should provide 3 independent, manually-verifiable test methods.
/// </summary>
public interface IMultiPathCheck : IHardeningCheck
{
    /// <summary>
    /// Runs 3 independent verification tests for this security check.
    /// Each test should use a different method (Registry, PowerShell cmdlet, CMD command, WMI, etc.)
    /// so users can manually verify results by running the same commands.
    /// </summary>
    /// <returns>List of 3 TestResult objects with real verification data</returns>
    Task<List<TestResult>> RunMultipleTestsAsync();
}