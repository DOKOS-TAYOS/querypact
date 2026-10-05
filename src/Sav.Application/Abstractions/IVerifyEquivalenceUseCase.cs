using Sav.Application.Verify;

namespace Sav.Application.Abstractions;

public interface IVerifyEquivalenceUseCase
{
    Task<VerifyEquivalenceResponse> ExecuteAsync(
        VerifyEquivalenceRequest request,
        CancellationToken cancellationToken);
}
