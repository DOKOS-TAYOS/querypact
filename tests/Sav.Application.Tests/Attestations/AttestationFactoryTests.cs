using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Attestations;

public sealed class AttestationFactoryTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x42, 32).ToArray();
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public void Create_rejects_hmac_key_shorter_than_32_bytes()
    {
        AttestationFactory factory = CreateFactory();
        byte[] weak = Enumerable.Repeat((byte)0x01, 16).ToArray();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => factory.Create(SampleDraft(), weak));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_redacts_then_signs_and_is_reproducible()
    {
        AttestationFactory factory = CreateFactory();
        AttestationDraft draft = SampleDraft(detail: "leak " + Canary);

        Attestation first = factory.Create(draft, Key);
        Attestation second = factory.Create(draft, Key);

        // Compatibility fixture computed from the accepted baseline's canonical bytes with Key.
        Assert.Equal("mz+/epGpBJZIywtnRunCklg2r7Tb6UbU+KhH5n/hd0k=", first.HmacSha256Base64);
        Assert.Equal(first.HmacSha256Base64, second.HmacSha256Base64);
        Assert.DoesNotContain(Canary, first.Properties[0].RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.True(AttestationFactory.VerifyIntegrity(first, new AttestationHmac(), Key));
        Assert.Equal("PASS", AttestationDecisionMapper.ToWire(first.Decision));
        Assert.Equal(AttestationMacMaterial.ComputeSqlHash("SELECT 1"), first.SqlHash);
    }

    [Fact]
    public void Create_does_not_embed_hmac_implementation_in_body_fields()
    {
        AttestationFactory factory = CreateFactory();
        Attestation attestation = factory.Create(SampleDraft(), Key);

        string bodyJson = CanonicalJson.Serialize(AttestationMacMaterial.ToCanonicalBody(attestation));
        Assert.DoesNotContain("hmacSha256Base64", bodyJson, StringComparison.Ordinal);
        Assert.Contains("\"decision\":\"PASS\"", bodyJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Hashes_are_stable_for_identical_inputs()
    {
        string sqlHash = AttestationMacMaterial.ComputeSqlHash("SELECT 1");
        string contractHash = AttestationMacMaterial.ComputeContractHash(new { name = "c1" });
        string policyHash = AttestationMacMaterial.ComputePolicyHash(new { name = "p1" });

        Assert.Equal(sqlHash, AttestationMacMaterial.ComputeSqlHash("SELECT 1"));
        Assert.Equal(contractHash, AttestationMacMaterial.ComputeContractHash(new { name = "c1" }));
        Assert.Equal(policyHash, AttestationMacMaterial.ComputePolicyHash(new { name = "p1" }));
        Assert.NotEqual(sqlHash, AttestationMacMaterial.ComputeSqlHash("SELECT 2"));
    }

    private static AttestationFactory CreateFactory() =>
        new(new AttestationHmac(), new CanaryAwareRedactor());

    private static AttestationDraft SampleDraft(string? detail = null)
    {
        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults();
        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["SelectStmt"],
            tablesRead: ["public.t"],
            tablesWritten: [],
            columnsRead: ["public.t.id"],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: []);

        return new AttestationDraft(
            SchemaVersion: "1",
            Id: "att-001",
            SqlHash: AttestationMacMaterial.ComputeSqlHash("SELECT 1"),
            ContractHash: AttestationMacMaterial.ComputeContractHash(new { name = "c1" }),
            PolicyHash: AttestationMacMaterial.ComputePolicyHash(new { name = "p1" }),
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "alias-fp",
            Decision: AttestationDecision.Pass,
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            PlanSummary: new PlanSummary("lt10", ["Seq Scan"], []),
            Properties:
            [
                new PropertyResult("query_succeeds", PropertyStatus.Pass, detail),
            ],
            EffectiveDisclosure: disclosure,
            Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z"));
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
