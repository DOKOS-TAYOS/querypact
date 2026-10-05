using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyEquivalenceResponsesRedactObjectTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x75, 32).ToArray();

    [Fact]
    public async Task Response_attestation_is_redacted_and_contains_no_canary()
    {
        CanaryResponseRedactor redactor = new();
        FakeStore store = new();

        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, "ok " + Canary),
        ]);

        VerifyEquivalenceUseCase useCase = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedEquivalenceContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new AttestationFactory(new AttestationHmac(), redactor),
            store,
            redactor,
            Key);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest("SELECT 1", "SELECT 2", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.True(redactor.VerifyEquivalenceResponseCalls >= 1);
        string json = CanonicalJson.Serialize(response.Attestation);
        Assert.DoesNotContain(Canary, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password=", json, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FakeStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }

    private sealed class CanaryResponseRedactor : IRedactor
    {
        public int VerifyEquivalenceResponseCalls { get; private set; }

        public string RedactText(string value, DisclosureProfile profile) =>
            value.Replace(Canary, "[REDACTED]", StringComparison.OrdinalIgnoreCase);

        public T RedactObject<T>(T value, DisclosureProfile profile)
        {
            if (value is string text)
            {
                return (T)(object)RedactText(text, profile);
            }

            if (value is PropertyResult property)
            {
                return (T)(object)new PropertyResult(
                    property.Name,
                    property.Status,
                    property.RedactedDetail is null ? null : RedactText(property.RedactedDetail, profile));
            }

            if (value is IReadOnlyList<PropertyResult> list)
            {
                return (T)(object)list.Select(p => RedactObject(p, profile)).ToArray();
            }

            if (value is Attestation attestation)
            {
                PropertyResult[] props = attestation.Properties
                    .Select(p => RedactObject(p, profile))
                    .ToArray();
                return (T)(object)new Attestation(
                    attestation.SchemaVersion,
                    attestation.Id,
                    attestation.SqlHash,
                    attestation.ContractHash,
                    attestation.PolicyHash,
                    attestation.SavVersion,
                    attestation.TargetAliasFingerprint,
                    attestation.Decision,
                    attestation.Analysis,
                    attestation.PlanSummary,
                    props,
                    attestation.EffectiveDisclosure,
                    attestation.Timestamp,
                    attestation.HmacSha256Base64);
            }

            if (value is VerifyEquivalenceResponse response)
            {
                VerifyEquivalenceResponseCalls++;
                Attestation redacted = RedactObject(response.Attestation, profile);
                return (T)(object)new VerifyEquivalenceResponse(response.AttestationId, redacted);
            }

            return value;
        }
    }
}
