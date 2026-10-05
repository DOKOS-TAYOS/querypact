using Sav.Application.Verify;

namespace Sav.Application.Abstractions;

public interface IVerifyQueryUseCase
{
    Task<VerifyQueryResponse> ExecuteAsync(
        VerifyQueryRequest request,
        CancellationToken cancellationToken);
}
