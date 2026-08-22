namespace ISCM.Domain.Entities;

/// <summary>
/// Represents the result of a single verification test method for a security check.
/// Used for multi-path testing where each check runs 3 independent verification methods.
/// </summary>
public class TestResult
{
    public string TestName { get; set; } = string.Empty;
    public string TestMethod { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Details { get; set; } = string.Empty;
    public DateTime ExecutedAt { get; set; } = DateTime.Now;

    public TestResult() { }

    public TestResult(string testName, string testMethod, bool passed, string details = "")
    {
        TestName = testName;
        TestMethod = testMethod;
        Passed = passed;
        Details = details;
        ExecutedAt = DateTime.Now;
    }
}