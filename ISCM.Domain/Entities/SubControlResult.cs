using System;
using System.Collections.Generic;
using ISCM.Domain.Enums;

namespace ISCM.Domain.Entities
{
    /// <summary>
    /// Represents the evaluation result of a single, independent security setting (SubControl).
    /// It aggregates one or more pieces of Evidence to determine its final Status.
    /// </summary>
    public class SubControlResult
    {
        public string SubControlId { get; set; } = string.Empty;
        public CheckStatus Status { get; set; }
        public List<Evidence> EvidenceItems { get; set; } = new();
        public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;
    }
}