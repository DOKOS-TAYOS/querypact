using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Profiling;

internal sealed class TimedReadOnlySessionFactory(
    IReadOnlySessionFactory inner,
    StageTimingCollector timings) : IReadOnlySessionFactory
{
    public Task<IReadOnlySession> OpenReadOnlySessionAsync(
        TargetAlias target,
        CancellationToken cancellationToken) =>
        timings.MeasureAsync(
            "session_open",
            () => inner.OpenReadOnlySessionAsync(target, cancellationToken));
}

internal sealed class TimedCatalogResolver(
    ICatalogResolver inner,
    StageTimingCollector timings) : ICatalogResolver
{
    public Task<SqlAnalysis> EnrichAsync(
        SqlAnalysis analysis,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken) =>
        timings.MeasureAsync(
            "catalog_enrich",
            () => inner.EnrichAsync(analysis, target, session, cancellationToken));
}

internal sealed class TimedSchemaFingerprintGuard(
    ISchemaFingerprintGuard inner,
    StageTimingCollector timings) : ISchemaFingerprintGuard
{
    public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        CancellationToken cancellationToken) =>
        timings.MeasureAsync(
            "fingerprint_capture",
            () => inner.CaptureBaselineAsync(session, target, analysis, cancellationToken));

    public async Task EnsureUnchangedAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        TargetSchemaFingerprint baseline,
        DateTimeOffset pipelineStartedUtc,
        CancellationToken cancellationToken)
    {
        await timings.MeasureAsync(
            "fingerprint_ensure",
            async () =>
            {
                await inner.EnsureUnchangedAsync(
                    session,
                    target,
                    analysis,
                    baseline,
                    pipelineStartedUtc,
                    cancellationToken);
                return true;
            });
    }
}

internal sealed class TimedPlanProvider(
    IPlanProvider inner,
    StageTimingCollector timings) : IPlanProvider
{
    public Task<PlanGateResult> GetEstimatedPlanAsync(
        TargetAlias target,
        string sql,
        PolicyDecision decision,
        Policy policy,
        IReadOnlySession? session,
        CancellationToken cancellationToken) =>
        timings.MeasureAsync(
            "plan",
            () => inner.GetEstimatedPlanAsync(target, sql, decision, policy, session, cancellationToken));
}

internal sealed class TimedPropertyOracle(
    IPropertyOracle inner,
    StageTimingCollector timings) : IPropertyOracle
{
    public Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken) =>
        timings.MeasureAsync(
            "property_oracle",
            () => inner.EvaluateAsync(request, cancellationToken));
}
