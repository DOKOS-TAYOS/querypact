using Sav.Domain.Attestations;

namespace Sav.Application.Abstractions;

public interface IAttestationStore
{
    Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken);

    Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken);
}
