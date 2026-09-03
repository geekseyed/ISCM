using ISCM.Domain.Entities;

namespace ISCM.Application.Interfaces;

public interface IEvidenceFingerprintGenerator
{
    string GenerateFingerprint(Evidence evidence);
    bool ValidateFingerprint(Evidence evidence, string expectedFingerprint);
}