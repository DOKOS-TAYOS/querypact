using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class SchemaFingerprintToctouTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x71, 32).ToArray();

    [Fact]
    public async Task Schema_drift_on_ensure_maps_to_review_attestation()
    {
        FakeStore store = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new SchemaChangedOnEnsureGuard(throwOnEnsureCall: 1),
            store);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, response.Attestation.Decision);
        Assert.Equal(response.AttestationId, response.Attestation.Id);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), Key));
        Assert.Contains(
            SavErrorCode.SchemaChanged,
            response.Attestation.Analysis.Ir.RiskCodes,
            StringComparer.Ordinal);
        Assert.Contains(
            response.Attestation.Properties,
            p => p.Name == "schema_fingerprint"
                 && p.Status == PropertyStatus.Fail
                 && p.RedactedDetail == SavErrorCode.SchemaChanged);
    }

    [Fact]
    public async Task Schema_drift_on_s3_maps_to_review_before_oracle_result()
    {
        FakeStore store = new();
        RecordingOracle oracle = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new SchemaChangedOnEnsureGuard(throwOnEnsureCall: 2),
            store,
            oracle);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, response.Attestation.Decision);
        Assert.Equal(0, oracle.CallCount);
        Assert.Contains(
            SavErrorCode.SchemaChanged,
            response.Attestation.Analysis.Ir.RiskCodes,
            StringComparer.Ordinal);
        Assert.Contains(
            response.Attestation.Properties,
                 p => p.RedactedDetail == SavErrorCode.SchemaChanged);
    }

    [Fact]
    public async Task Schema_guard_time_budget_starts_before_configuration_load()
    {
        FakeStore store = new();
        TimestampRecordingGuard guard = new();
        DelayedPolicyLoader policyLoader = new();
        VerifyQueryUseCase useCase = CreateUseCase(guard, store, policyLoader: policyLoader);

        await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.NotNull(policyLoader.LoadStartedUtc);
        Assert.NotNull(guard.FirstPipelineStartedUtc);
        Assert.True(guard.FirstPipelineStartedUtc <= policyLoader.LoadStartedUtc);
    }

    private static VerifyQueryUseCase CreateUseCase(
        ISchemaFingerprintGuard guard,
        FakeStore store,
        RecordingOracle? oracle = null,
        IPolicyLoader? policyLoader = null)
    {
        IPolicyLoader configuredPolicyLoader = policyLoader ?? new FixedPolicyLoader();
        FixedParser parser = new(success: true);
        VerificationPipeline pipeline = new(
            parser,
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            configuredPolicyLoader,
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle ?? new RecordingOracle(),
            guard,
            new PipelineRecordingRedactor());

        return new VerifyQueryUseCase(
            pipeline,
            parser,
            configuredPolicyLoader,
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new AttestationFactory(new AttestationHmac(), new PipelineRecordingRedactor()),
            store,
            new PipelineRecordingRedactor(),
            Key);
    }

    private sealed class SchemaChangedOnEnsureGuard : ISchemaFingerprintGuard
    {
        private readonly int _throwOnEnsureCall;
        private int _ensureCount;

        public SchemaChangedOnEnsureGuard(int throwOnEnsureCall)
        {
            _throwOnEnsureCall = throwOnEnsureCall;
        }

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TargetSchemaFingerprint("baseline"));

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            _ensureCount++;
            if (_ensureCount == _throwOnEnsureCall)
            {
                throw new SavException(SavErrorCode.SchemaChanged, "schema_changed: drift");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TimestampRecordingGuard : ISchemaFingerprintGuard
    {
        public DateTimeOffset? FirstPipelineStartedUtc { get; private set; }

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TargetSchemaFingerprint("baseline"));

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            FirstPipelineStartedUtc ??= pipelineStartedUtc;
            return Task.CompletedTask;
        }
    }

    private sealed class DelayedPolicyLoader : IPolicyLoader
    {
        private readonly FixedPolicyLoader _inner = new();

        public DateTimeOffset? LoadStartedUtc { get; private set; }

        public async Task<Policy> LoadAsync(string path, CancellationToken cancellationToken)
        {
            LoadStartedUtc = DateTimeOffset.UtcNow;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
            return await _inner.LoadAsync(path, cancellationToken);
        }
    }

    private sealed class FakeStore : IAttestationStore
    {
        public Dictionary<string, Attestation> Saved { get; } = new(StringComparer.Ordinal);

        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken)
        {
            Saved[attestation.Id] = attestation;
            return Task.FromResult(attestation.Id);
        }

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult(Saved.TryGetValue(attestationId, out Attestation? a) ? a : null);
    }
}
