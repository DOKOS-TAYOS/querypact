using Sav.Domain.Analysis;
using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Resolves objects in <see cref="SqlAnalysis"/> against pg_catalog using the pipeline-opened session.
/// Does not open sessions or produce <c>TargetSchemaFingerprint</c>.
/// </summary>
public interface ICatalogResolver
{
    Task<SqlAnalysis> EnrichAsync(
        SqlAnalysis analysis,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken);
}
