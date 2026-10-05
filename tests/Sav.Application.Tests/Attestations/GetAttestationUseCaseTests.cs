using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Attestations;

public sealed class GetAttestationUseCaseTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x7A, 32).ToArray();
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public async Task Execute_returns_null_when_missing()
    {
        GetAttestationUseCase useCase = CreateUseCase(new FakeStore());
        Attestation? result = await useCase.ExecuteAsync("missing", CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task Execute_returns_attestation_when_hmac_valid()
    {
        AttestationFactory factory = new(new AttestationHmac(), new CanaryAwareRedactor());
        Attestation created = factory.Create(SampleDraft(detail: null), Key);
        FakeStore store = new();
        await store.SaveAsync(created, CancellationToken.None);

        GetAttestationUseCase useCase = CreateUseCase(store);
        Attestation? loaded = await useCase.ExecuteAsync(created.Id, CancellationToken.None);

        Assert.NotNull(loaded);
        Assert.Equal(created.HmacSha256Base64, loaded.HmacSha256Base64);
        Assert.Equal(created.SqlHash, loaded.SqlHash);
    }

    [Fact]
    public async Task Execute_throws_integrity_failure_when_body_tampered()
    {
        AttestationFactory factory = new(new AttestationHmac(), new CanaryAwareRedactor());
        Attestation created = factory.Create(SampleDraft(), Key);
        Attestation tampered = new(
            created.SchemaVersion,
            created.Id,
            sqlHash: "tampered-hash",
            created.ContractHash,
            created.PolicyHash,
            created.SavVersion,
            created.TargetAliasFingerprint,
            created.Decision,
            created.Analysis,
            created.PlanSummary,
            created.Properties,
            created.EffectiveDisclosure,
            created.Timestamp,
            created.HmacSha256Base64);

        FakeStore store = new();
        await store.SaveAsync(tampered, CancellationToken.None);

        GetAttestationUseCase useCase = CreateUseCase(store);
        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => useCase.ExecuteAsync(tampered.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Execute_redacts_canary_in_stored_detail_before_return_when_unsigned_path_scrubbed()
    {
        // Stored body already signed after redaction: canary must not be present.
        AttestationFactory factory = new(new AttestationHmac(), new CanaryAwareRedactor());
        Attestation created = factory.Create(SampleDraft(detail: "x " + Canary), Key);
        Assert.DoesNotContain(Canary, created.Properties[0].RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        FakeStore store = new();
        await store.SaveAsync(created, CancellationToken.None);
        GetAttestationUseCase useCase = CreateUseCase(store);
        Attestation? loaded = await useCase.ExecuteAsync(created.Id, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.DoesNotContain(Canary, loaded.Properties[0].RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Constructor_rejects_hmac_key_shorter_than_32_bytes()
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(() =>
            new GetAttestationUseCase(
                new FakeStore(),
                new AttestationHmac(),
                new CanaryAwareRedactor(),
                Enumerable.Repeat((byte)0x01, 31).ToArray()));

        Assert.Equal("hmacKey", ex.ParamName);
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    private static GetAttestationUseCase CreateUseCase(IAttestationStore store) =>
        new(store, new AttestationHmac(), new CanaryAwareRedactor(), Key);

    private static AttestationDraft SampleDraft(string? detail = "ok")
    {
        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults();
        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["SelectStmt"],
            tablesRead: [],
            tablesWritten: [],
            columnsRead: [],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: []);

        return new AttestationDraft(
            SchemaVersion: "1",
            Id: "att-get-1",
            SqlHash: AttestationMacMaterial.ComputeSqlHash("SELECT 1"),
            ContractHash: "c",
            PolicyHash: "p",
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "fp",
            Decision: AttestationDecision.Deny,
            Analysis: new AttestationAnalysis(ir, IsParsable: false),
            PlanSummary: null,
            Properties: [new PropertyResult("query_succeeds", PropertyStatus.Fail, detail)],
            EffectiveDisclosure: disclosure,
            Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z"));
    }

    private sealed class FakeStore : IAttestationStore
    {
        private readonly Dictionary<string, Attestation> _items = new(StringComparer.Ordinal);

        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken)
        {
            _items[attestation.Id] = attestation;
            return Task.FromResult(attestation.Id);
        }

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken)
        {
            _items.TryGetValue(attestationId, out Attestation? value);
            return Task.FromResult(value);
        }
    }

    private sealed class CanaryAwareRedactor : IRedactor
    {
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

            return value;
        }
    }
}
