using ISCM.Domain.Enums;

namespace ISCM.Application.Interfaces
{
    /// <summary>
    /// Responsible for comparing a ParsedValue against an ExpectedValue and determining compliance.
    /// </summary>
    public interface IEvidenceEvaluator
    {
        /// <summary>
        /// Evaluates compliance based on parsed data and expected rules.
        /// </summary>
        /// <param name="parsedValue">The actual value found on the system.</param>
        /// <param name="expectedValue">The compliant value defined in the baseline.</param>
        /// <param name="evaluationRule">Optional: A specific rule like ">=", "==", "Contains".</param>
        /// <returns>A tuple containing the CheckStatus and a human-readable reason.</returns>
        (CheckStatus Status, string Reason) Evaluate(string parsedValue, string expectedValue, string? evaluationRule = null);
    }
}