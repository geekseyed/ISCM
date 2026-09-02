namespace ISCM.Domain.Entities;

public class VerificationPath
{
    public string PathId { get; set; }
    public string Source { get; set; }
    public string AcquisitionMechanism { get; set; }
    public string IndependenceClass { get; set; }
    public bool IsAvailable { get; set; }
}