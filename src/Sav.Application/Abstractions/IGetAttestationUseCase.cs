using Sav.Domain.Attestations;

namespace Sav.Application.Abstractions;

public interface IGetAttestationUseCase
{
    Task<Attestation?> ExecuteAsync(string attestationId, CancellationToken cancellationToken);
}
