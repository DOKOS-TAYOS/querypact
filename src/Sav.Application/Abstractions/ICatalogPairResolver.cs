using Sav.Domain.Analysis;
using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Enriches both sides of an equivalence request using one catalog snapshot and session.
/// </summary>
public interface ICatalogPairResolver : ICatalogResolver
{
    Task<(SqlAnalysis Left, SqlAnalysis Right)> EnrichPairAsync(
        SqlAnalysis left,
        SqlAnalysis right,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken);
}
