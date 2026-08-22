namespace ISCM.Domain.Entities;

// EDIT (گروه C - C6): نتیجهٔ یک روش تست برای یک چک امنیتی
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