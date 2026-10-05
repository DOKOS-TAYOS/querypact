using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyQueryAttestHmacOrderTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x72, 32).ToArray();

    [Fact]
    public async Task Pipeline_path_redacts_before_hmac_sign()
    {
        OrderClock clock = new();
        OrderTrackingRedactor redactor = new(clock);
        OrderTrackingMac mac = new(clock);
        FakeStore store = new();

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
            new RecordingOracle(),
            new RecordingGuard(),
            redactor);

        VerifyQueryUseCase useCase = new(
            pipeline,
            new FixedParser(success: true),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new AttestationFactory(mac, redactor),
            store,
            redactor,
            Key);

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.True(redactor.AttestationRedactCount >= 1);
        Assert.Equal(1, mac.ComputeCount);
        Assert.True(redactor.LastAttestationRedactSequence < mac.LastComputeSequence);
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), Key));
    }

    private sealed class OrderClock
    {
        private int _sequence;

        public int Next() => ++_sequence;
    }

    private sealed class OrderTrackingRedactor : IRedactor
    {
        private readonly OrderClock _clock;

        public OrderTrackingRedactor(OrderClock clock)
        {
            _clock = clock;
        }

        public int AttestationRedactCount { get; private set; }

        public int LastAttestationRedactSequence { get; private set; }

        public string RedactText(string value, DisclosureProfile profile) => value;

        public T RedactObject<T>(T value, DisclosureProfile profile)
        {
            if (value is Attestation)
            {
                AttestationRedactCount++;
                LastAttestationRedactSequence = _clock.Next();
            }

            return value;
        }
    }

    private sealed class OrderTrackingMac : IAttestationMac
    {
        private readonly OrderClock _clock;

        public OrderTrackingMac(OrderClock clock)
        {
            _clock = clock;
        }

        public int ComputeCount { get; private set; }

        public int LastComputeSequence { get; private set; }

        public string ComputeBase64(ReadOnlySpan<byte> canonicalRedactedBodyUtf8, ReadOnlySpan<byte> key)
        {
            ComputeCount++;
            LastComputeSequence = _clock.Next();
            return new AttestationHmac().ComputeBase64(canonicalRedactedBodyUtf8, key);
        }
    }

    private sealed class FakeStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }
}
