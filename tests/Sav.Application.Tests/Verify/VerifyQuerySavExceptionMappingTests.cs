using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyQuerySavExceptionMappingTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x5A, 32).ToArray();

    [Fact]
    public async Task Query_failed_from_plan_maps_to_fail_attestation_not_raw_throw()
    {
        FakeStore store = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new ThrowingPlanProvider(new SavException(SavErrorCode.QueryFailed, "EXPLAIN blew up with relation orders")),
            store);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, response.Attestation.Decision);
        PropertyResult detail = Assert.Single(response.Attestation.Properties);
        Assert.Equal("verify_query", detail.Name);
        Assert.Equal(SavErrorCode.QueryFailed, detail.RedactedDetail);
        Assert.DoesNotContain("relation", detail.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("orders", detail.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
    }

    [Fact]
    public async Task Alias_unknown_maps_to_deny_attestation()
    {
        FakeStore store = new();
        FixedParser parser = new(success: true);
        VerificationPipeline pipeline = new(
            parser,
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new ThrowingAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerifyQueryUseCase useCase = new(
            pipeline,
            parser,
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new ThrowingAliasResolver(),
            new AttestationFactory(new AttestationHmac(), new PipelineRecordingRedactor()),
            store,
            new PipelineRecordingRedactor(),
            Key);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "missing", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Equal(SavErrorCode.AliasUnknown, Assert.Single(response.Attestation.Properties).RedactedDetail);
    }

    [Fact]
    public async Task Unexpected_exception_maps_to_deny_with_query_failed()
    {
        FakeStore store = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new ThrowingPlanProvider(new InvalidOperationException("raw stack should not leak Host=evil")),
            store);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        PropertyResult detail = Assert.Single(response.Attestation.Properties);
        Assert.Equal(SavErrorCode.QueryFailed, detail.RedactedDetail);
        Assert.DoesNotContain("Host=", detail.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw stack", detail.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
    }

    private static VerifyQueryUseCase CreateUseCase(IPlanProvider plan, FakeStore store)
    {
        FixedParser parser = new(success: true);
        VerificationPipeline pipeline = new(
            parser,
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            plan,
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        return new VerifyQueryUseCase(
            pipeline,
            parser,
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new AttestationFactory(new AttestationHmac(), new PipelineRecordingRedactor()),
            store,
            new PipelineRecordingRedactor(),
            Key);
    }

    private sealed class ThrowingPlanProvider : IPlanProvider
    {
        private readonly Exception _ex;

        public ThrowingPlanProvider(Exception ex) => _ex = ex;

        public Task<PlanGateResult> GetEstimatedPlanAsync(
            Domain.Targets.TargetAlias target,
            string sql,
            PolicyDecision decision,
            Domain.Policies.Policy policy,
            IReadOnlySession? session,
            CancellationToken cancellationToken) =>
            Task.FromException<PlanGateResult>(_ex);
    }

    private sealed class ThrowingAliasResolver : ITargetAliasResolver
    {
        public Domain.Targets.TargetAlias Resolve(string aliasName) =>
            throw new SavException(SavErrorCode.AliasUnknown, "alias_unknown: " + aliasName);
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
