using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyQueryUseCaseTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x73, 32).ToArray();

    [Fact]
    public async Task Deny_unparsable_persists_deny_attestation()
    {
        FakeStore store = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new FixedParser(success: false),
            new ScriptedPolicyEngine(new PolicyDecision(PolicyOutcome.Deny, ["sql_unparsable"], ["sql_unparsable"])),
            store);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.False(response.Attestation.Analysis.IsParsable);
        Assert.Equal(response.AttestationId, response.Attestation.Id);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), Key));
    }

    [Fact]
    public async Task Allow_path_persists_pass_with_mvp_a_properties()
    {
        FakeStore store = new();
        VerifyQueryUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            store);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Equal(2, response.Attestation.Properties.Count);
        Assert.Contains(response.Attestation.Properties, p => p.Name == "query_succeeds");
        Assert.Contains(response.Attestation.Properties, p => p.Name == "empty_result");
        Assert.Equal("alias-fp", response.Attestation.TargetAliasFingerprint);
        Assert.NotNull(response.Attestation.PlanSummary);
    }

    [Fact]
    public async Task Fail_properties_persist_fail_decision()
    {
        FakeStore store = new();
        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_succeeds", PropertyStatus.Fail, "query_failed"),
            new PropertyResult("empty_result", PropertyStatus.Error, "query_failed"),
        ]);

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerifyQueryUseCase useCase = new(
            pipeline,
            new FixedParser(success: true),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new AttestationFactory(new AttestationHmac(), new PipelineRecordingRedactor()),
            store,
            new PipelineRecordingRedactor(),
            Key);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, response.Attestation.Decision);
    }

    private static VerifyQueryUseCase CreateUseCase(
        FixedParser parser,
        ScriptedPolicyEngine engine,
        FakeStore store)
    {
        VerificationPipeline pipeline = new(
            parser,
            engine,
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
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

    private static VerifyQueryRequest SampleRequest() =>
        new("SELECT 1", "demo", "policy.yaml", "contract.yaml");

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
