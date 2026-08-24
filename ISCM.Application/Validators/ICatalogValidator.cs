namespace ISCM.Application.Validators;

/// <summary>
/// Interface for validating the integrity of the Control Catalog and DI registrations.
/// </summary>
public interface ICatalogValidator
{
    /// <summary>
    /// Validates the catalog. Throws InvalidOperationException if integrity rules are violated.
    /// </summary>
    void Validate();
}