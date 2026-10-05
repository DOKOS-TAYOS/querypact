using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyEquivalenceUseCaseTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x73, 32).ToArray();

    [Fact]
    public async Task Unparsable_left_or_right_persists_deny_attestation_without_session_open()
    {
        FakeStore store = new();
        RecordingSessionFactory sessions = new();
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: false),
            new ScriptedPolicyEngine(),
            store,
            sessions);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.False(response.Attestation.Analysis.IsParsable);
        Assert.Equal(0, sessions.OpenCount);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), Key));
    }

    [Fact]
    public async Task First_policy_deny_short_circuits_before_session_open()
    {
        FakeStore store = new();
        RecordingSessionFactory sessions = new();
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Deny, ["denied_table"], ["denied_table"]),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            store,
            sessions);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Empty(response.Attestation.Properties);
        Assert.Equal(0, sessions.OpenCount);
    }

    [Fact]
    public async Task Allow_path_evaluates_query_equivalent_and_persists_pass()
    {
        FakeStore store = new();
        RecordingSessionFactory sessions = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);

        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(),
            store,
            sessions,
            oracle);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
        Assert.Contains(response.Attestation.Properties, p => p.Name == "query_equivalent");
        Assert.Equal("alias-fp", response.Attestation.TargetAliasFingerprint);
        Assert.NotNull(oracle.LastRequest);
        Assert.Equal("SELECT 1", oracle.LastRequest!.LeftSql);
        Assert.Equal("SELECT 2", oracle.LastRequest!.RightSql);
        Assert.NotNull(oracle.LastRequest!.RightIr);
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), Key));
    }

    [Fact]
    public async Task Not_equivalent_property_persists_fail_decision()
    {
        FakeStore store = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Fail, "not_equivalent"),
        ]);

        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(),
            store,
            new RecordingSessionFactory(),
            oracle);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, response.Attestation.Decision);
    }

    [Fact]
    public async Task Unsupported_contract_properties_cannot_produce_pass()
    {
        FakeStore store = new();
        RecordingSessionFactory sessions = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        Contract unsupported = new(
            "c",
            "1",
            [new QueryEquivalentSpec(), new AffectedRowsSpec(0, 100)],
            DisclosureProfileMerge.StrictDefaults());

        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(),
            store,
            sessions,
            oracle,
            contractLoader: new ConfigurableContractLoader(unsupported));

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.NotEqual(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, oracle.CallCount);
    }

    [Fact]
    public async Task Session_is_disposed_even_when_oracle_throws()
    {
        FakeStore store = new();
        RecordingSessionFactory sessions = new();
        ThrowingOracle oracle = new();

        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(),
            store,
            sessions,
            oracle);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
    }

    [Theory]
    [InlineData(PlanGateOutcome.Deny, AttestationDecision.Deny)]
    [InlineData(PlanGateOutcome.Review, AttestationDecision.Review)]
    public async Task Plan_deny_or_review_skips_oracle(
        PlanGateOutcome planOutcome,
        AttestationDecision expectedDecision)
    {
        FakeStore store = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        RecordingPlanProvider plan = new(planOutcome);

        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(),
            store,
            new RecordingSessionFactory(),
            oracle,
            plan);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            SampleRequest(),
            CancellationToken.None);

        Assert.Equal(expectedDecision, response.Attestation.Decision);
        Assert.True(plan.CallCount >= 1);
        Assert.Equal(0, oracle.CallCount);
    }

    private static VerifyEquivalenceUseCase CreateUseCase(
        FixedParser parser,
        ScriptedPolicyEngine engine,
        FakeStore store,
        RecordingSessionFactory sessions,
        IPropertyOracle? oracle = null,
        IPlanProvider? plan = null,
        IContractLoader? contractLoader = null)
    {
        PipelineRecordingRedactor redactor = new();
        return new VerifyEquivalenceUseCase(
            parser,
            engine,
            new FixedPolicyLoader(),
            contractLoader ?? new ConfigurableContractLoader(
                new Contract(
                    "c",
                    "1",
                    [new QueryEquivalentSpec()],
                    DisclosureProfileMerge.StrictDefaults())),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            new RecordingCatalog(),
            plan ?? new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle ?? new RecordingOracle(),
            new RecordingGuard(),
            new AttestationFactory(new AttestationHmac(), redactor),
            store,
            redactor,
            Key);
    }

    private static VerifyEquivalenceRequest SampleRequest() =>
        new("SELECT 1", "SELECT 2", "demo", "policy.yaml", "contract.yaml");

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

    private sealed class ThrowingOracle : IPropertyOracle
    {
        public Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
            PropertyEvaluationRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("boom");
    }
}
