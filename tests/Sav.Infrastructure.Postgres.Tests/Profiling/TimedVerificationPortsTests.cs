using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Tests.Profiling;

public sealed class TimedVerificationPortsTests
{
    [Fact]
    public async Task Timed_ports_forward_values_and_cancellation_tokens_to_each_inner_port()
    {
        using CancellationTokenSource cancellation = new();
        CancellationToken token = cancellation.Token;
        StageTimingCollector timings = new();
        TestSession session = new();
        TargetAlias target = new("target", "fingerprint");
        SqlAnalysis analysis = CreateAnalysis();
        TargetSchemaFingerprint fingerprint = new("baseline");
        PlanGateResult planResult = new(PlanGateOutcome.Allow, [], null);
        IReadOnlyList<PropertyResult> propertyResults = [new("query_succeeds", PropertyStatus.Pass, null)];

        RecordingSessionFactory sessionFactory = new(session);
        RecordingCatalogResolver catalogResolver = new(analysis);
        RecordingFingerprintGuard fingerprintGuard = new(fingerprint);
        RecordingPlanProvider planProvider = new(planResult);
        RecordingPropertyOracle propertyOracle = new(propertyResults);

        IReadOnlySession openedSession = await new TimedReadOnlySessionFactory(sessionFactory, timings)
            .OpenReadOnlySessionAsync(target, token);
        SqlAnalysis enriched = await new TimedCatalogResolver(catalogResolver, timings)
            .EnrichAsync(analysis, target, session, token);
        TargetSchemaFingerprint captured = await new TimedSchemaFingerprintGuard(fingerprintGuard, timings)
            .CaptureBaselineAsync(session, target, analysis, token);
        await new TimedSchemaFingerprintGuard(fingerprintGuard, timings).EnsureUnchangedAsync(
            session,
            target,
            analysis,
            fingerprint,
            DateTimeOffset.UnixEpoch,
            token);
        PlanGateResult plan = await new TimedPlanProvider(planProvider, timings).GetEstimatedPlanAsync(
            target,
            "SELECT 1",
            null!,
            null!,
            session,
            token);
        IReadOnlyList<PropertyResult> properties = await new TimedPropertyOracle(propertyOracle, timings)
            .EvaluateAsync(null!, token);

        Assert.Same(session, openedSession);
        Assert.Same(analysis, enriched);
        Assert.Same(fingerprint, captured);
        Assert.Same(planResult, plan);
        Assert.Same(propertyResults, properties);
        Assert.Equal(token, sessionFactory.CancellationToken);
        Assert.Equal(token, catalogResolver.CancellationToken);
        Assert.Equal(token, fingerprintGuard.CaptureCancellationToken);
        Assert.Equal(token, fingerprintGuard.EnsureCancellationToken);
        Assert.Equal(token, planProvider.CancellationToken);
        Assert.Equal(token, propertyOracle.CancellationToken);
        Assert.Equal(1, timings.GetSnapshot("session_open").CallCount);
        Assert.Equal(1, timings.GetSnapshot("catalog_enrich").CallCount);
        Assert.Equal(1, timings.GetSnapshot("fingerprint_capture").CallCount);
        Assert.Equal(1, timings.GetSnapshot("fingerprint_ensure").CallCount);
        Assert.Equal(1, timings.GetSnapshot("plan").CallCount);
        Assert.Equal(1, timings.GetSnapshot("property_oracle").CallCount);
    }

    private static SqlAnalysis CreateAnalysis() => new(
        new SqlIr("postgresql", ["Select"], [], [], [], [], [], false, false, [], [], "SELECT 1", "fp"),
        IsParsable: true);

    private sealed class TestSession : IReadOnlySession
    {
        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<OracleScalarRow>>([]);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingSessionFactory(IReadOnlySession result) : IReadOnlySessionFactory
    {
        public CancellationToken CancellationToken { get; private set; }

        public Task<IReadOnlySession> OpenReadOnlySessionAsync(TargetAlias target, CancellationToken cancellationToken)
        {
            CancellationToken = cancellationToken;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingCatalogResolver(SqlAnalysis result) : ICatalogResolver
    {
        public CancellationToken CancellationToken { get; private set; }

        public Task<SqlAnalysis> EnrichAsync(
            SqlAnalysis analysis,
            TargetAlias target,
            IReadOnlySession session,
            CancellationToken cancellationToken)
        {
            CancellationToken = cancellationToken;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingFingerprintGuard(TargetSchemaFingerprint result) : ISchemaFingerprintGuard
    {
        public CancellationToken CaptureCancellationToken { get; private set; }

        public CancellationToken EnsureCancellationToken { get; private set; }

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken)
        {
            CaptureCancellationToken = cancellationToken;
            return Task.FromResult(result);
        }

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            EnsureCancellationToken = cancellationToken;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingPlanProvider(PlanGateResult result) : IPlanProvider
    {
        public CancellationToken CancellationToken { get; private set; }

        public Task<PlanGateResult> GetEstimatedPlanAsync(
            TargetAlias target,
            string sql,
            PolicyDecision decision,
            Policy policy,
            IReadOnlySession? session,
            CancellationToken cancellationToken)
        {
            CancellationToken = cancellationToken;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingPropertyOracle(IReadOnlyList<PropertyResult> result) : IPropertyOracle
    {
        public CancellationToken CancellationToken { get; private set; }

        public Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
            PropertyEvaluationRequest request,
            CancellationToken cancellationToken)
        {
            CancellationToken = cancellationToken;
            return Task.FromResult(result);
        }
    }
}
