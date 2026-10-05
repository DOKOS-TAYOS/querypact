using Sav.Domain.Analysis;
using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Captures and re-checks <see cref="TargetSchemaFingerprint"/> on the pipeline-opened session.
/// Does not call <see cref="IReadOnlySessionFactory"/>.
/// </summary>
public interface ISchemaFingerprintGuard
{
    Task<TargetSchemaFingerprint> CaptureBaselineAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        CancellationToken cancellationToken);

    Task EnsureUnchangedAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        TargetSchemaFingerprint baseline,
        DateTimeOffset pipelineStartedUtc,
        CancellationToken cancellationToken);
}
