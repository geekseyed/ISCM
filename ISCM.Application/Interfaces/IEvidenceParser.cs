namespace ISCM.Application.Interfaces
{
    /// <summary>
    /// Responsible for converting raw, unstructured OS output into a structured ParsedValue.
    /// This separates the "how to read" logic from the "is it compliant" logic.
    /// </summary>
    public interface IEvidenceParser
    {
        /// <summary>
        /// Parses the raw output of a specific command or registry query.
        /// </summary>
        /// <param name="rawOutput">The exact string returned by the OS.</param>
        /// <param name="sourceType">The type of source (to choose the right parsing logic).</param>
        /// <returns>The structured value (as a string for serialization).</returns>
        string Parse(string rawOutput, string sourceType);
    }
}