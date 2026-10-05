using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Migrations;
using Sav.Application.Tests.Analyze;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Migrations;

public sealed class VerifyMigrationResponseRedactionTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x53, 32).ToArray();

    [Fact]
    public async Task Response_attestation_is_redacted_and_contains_no_canary()
    {
        CanaryRedactor redactor = new();
        VerifyMigrationUseCase useCase = new(
            new FakeParser(success: false),
            new FakePolicyEngine(PolicyOutcome.Deny, ["sql_unparsable", Canary]),
            new FakePolicyLoader(CreatePolicy()),
            new FakeContractLoader(CreateContract()),
            new FakePathResolver(),
            new NeverShadow(),
            new AttestationFactory(new AttestationHmac(), redactor),
            new InMemoryStore(),
            redactor,
            Key);

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "SELEC " + Canary,
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        string json = Domain.Serialization.CanonicalJson.Serialize(response.Attestation);
        Assert.DoesNotContain(Canary, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password=", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Host=", json, StringComparison.OrdinalIgnoreCase);
        Assert.True(redactor.VerifyMigrationResponseCalls >= 1);
    }

    private static Policy CreatePolicy() =>
        new(
            "p",
            "1",
            ["AlterTable"],
            [],
            [],
            [],
            false,
            true,
            true,
            "high",
            [],
            DisclosureProfileMerge.StrictDefaults());

    private static Contract CreateContract() =>
        new(
            "c",
            "1",
            [new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")])],
            DisclosureProfileMerge.StrictDefaults());

    private sealed class NeverShadow : IShadowMigrationRunner
    {
        public Task<ShadowMigrationOutcome> RunAsync(
            ShadowMigrationCommand command,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Shadow must not run on deny path.");
    }

    private sealed class InMemoryStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }

    private sealed class CanaryRedactor : IRedactor
    {
        public int VerifyMigrationResponseCalls { get; private set; }

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
                string? detail = property.RedactedDetail is null
                    ? null
                    : RedactText(property.RedactedDetail, profile);
                return (T)(object)new PropertyResult(property.Name, property.Status, detail);
            }

            if (value is IReadOnlyList<PropertyResult> list)
            {
                return (T)(object)list.Select(p => RedactObject(p, profile)).ToArray();
            }

            if (value is Attestation attestation)
            {
                IReadOnlyList<PropertyResult> props = attestation.Properties
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

            if (value is VerifyMigrationResponse response)
            {
                VerifyMigrationResponseCalls++;
                Attestation redacted = RedactObject(response.Attestation, profile);
                return (T)(object)new VerifyMigrationResponse(response.AttestationId, redacted);
            }

            return value;
        }
    }
}
