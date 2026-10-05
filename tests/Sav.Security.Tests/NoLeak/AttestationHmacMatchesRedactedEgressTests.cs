using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.NoLeak;

/// <summary>
/// HMAC verifies the already-redacted attestation body; post-sign mutation fails (M007b-factory-get gap).
/// </summary>
public sealed class AttestationHmacMatchesRedactedEgressTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0xA5, 32).ToArray();
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public void Hmac_matches_redacted_body_and_rejects_post_sign_mutation()
    {
        AttestationFactory factory = new(new AttestationHmac(), new CanaryAwareRedactor());
        AttestationDraft draft = SampleDraft(detail: "leak " + Canary);

        Attestation signed = factory.Create(draft, Key);

        Assert.DoesNotContain(Canary, signed.Properties[0].RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED]", signed.Properties[0].RedactedDetail ?? string.Empty, StringComparison.Ordinal);
        Assert.True(AttestationFactory.VerifyIntegrity(signed, new AttestationHmac(), Key));

        Attestation mutated = WithMutatedDetail(signed, "leak " + Canary);
        Assert.False(AttestationFactory.VerifyIntegrity(mutated, new AttestationHmac(), Key));
    }

    private static Attestation WithMutatedDetail(Attestation source, string detail) =>
        new(
            source.SchemaVersion,
            source.Id,
            source.SqlHash,
            source.ContractHash,
            source.PolicyHash,
            source.SavVersion,
            source.TargetAliasFingerprint,
            source.Decision,
            source.Analysis,
            source.PlanSummary,
            [new PropertyResult(source.Properties[0].Name, source.Properties[0].Status, detail)],
            source.EffectiveDisclosure,
            source.Timestamp,
            source.HmacSha256Base64);

    private static AttestationDraft SampleDraft(string? detail)
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
            Id: "att-hmac-redact-001",
            SqlHash: AttestationMacMaterial.ComputeSqlHash("SELECT 1"),
            ContractHash: AttestationMacMaterial.ComputeContractHash(new { name = "c1" }),
            PolicyHash: AttestationMacMaterial.ComputePolicyHash(new { name = "p1" }),
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "alias-fp",
            Decision: AttestationDecision.Pass,
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            PlanSummary: new PlanSummary("lt10", ["Seq Scan"], []),
            Properties: [new PropertyResult("query_succeeds", PropertyStatus.Pass, detail)],
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
