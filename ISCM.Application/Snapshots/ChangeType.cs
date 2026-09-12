namespace ISCM.Application.Snapshots;

/// <summary>
/// Classification of a change between two snapshots.
/// Used across Control, SubControl, Evidence, and Finding levels.
/// </summary>
public enum ChangeType
{
    /// <summary>Item exists in target but not in source (newly added).</summary>
    Added,

    /// <summary>Item exists in source but not in target (removed).</summary>
    Removed,

    /// <summary>Item improved (e.g., Fail → Pass, Unknown → Pass).</summary>
    Improved,

    /// <summary>Item regressed (e.g., Pass → Fail, Pass → Unknown).</summary>
    Regressed,

    /// <summary>Item changed but status remained the same (e.g., different evidence).</summary>
    Changed,

    /// <summary>Item is identical in both snapshots.</summary>
    Unchanged
}