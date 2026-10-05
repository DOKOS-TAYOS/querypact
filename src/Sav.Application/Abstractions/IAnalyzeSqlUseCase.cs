using Sav.Application.Analyze;

namespace Sav.Application.Abstractions;

public interface IAnalyzeSqlUseCase
{
    Task<AnalyzeSqlResponse> ExecuteAsync(AnalyzeSqlRequest request, CancellationToken cancellationToken);
}
