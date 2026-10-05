using Sav.Domain.Properties;

namespace Sav.Application.Abstractions;

/// <summary>
/// Property oracle. On a real alias, <see cref="PropertyEvaluationRequest.Session"/> must be
/// the pipeline-opened session: do not open another via <see cref="IReadOnlySessionFactory"/>.
/// </summary>
public interface IPropertyOracle
{
    Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken);
}
