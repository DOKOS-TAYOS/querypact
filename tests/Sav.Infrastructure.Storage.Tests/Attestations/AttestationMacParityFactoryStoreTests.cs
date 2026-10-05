using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

public sealed class AttestationMacParityFactoryStoreTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x33, 32).ToArray();

    [Fact]
    public void Factory_hmac_equals_store_recompute_for_same_canonical_body_and_key()
    {
        IAttestationMac mac = new AttestationHmac();
        AttestationFactory factory = new(mac, new PassThroughTestRedactor());
        AttestationDraft draft = SampleDraft();
        Attestation created = factory.Create(draft, Key);

        // Store-side verify path: recompute via the same IAttestationMac over canonical body.
        StoreSideVerifier storeVerifier = new(mac, Key);
        string storeRecomputed = storeVerifier.RecomputeHmac(created);

        Assert.Equal(created.HmacSha256Base64, storeRecomputed);
        Assert.True(storeVerifier.Verify(created));
    }

    private static AttestationDraft SampleDraft()
    {
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
            Id: "parity-1",
            SqlHash: AttestationMacMaterial.ComputeSqlHash("SELECT 1"),
            ContractHash: "c",
            PolicyHash: "p",
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "fp",
            Decision: AttestationDecision.Pass,
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            PlanSummary: null,
            Properties: [new PropertyResult("query_succeeds", PropertyStatus.Pass, null)],
            EffectiveDisclosure: DisclosureProfileMerge.StrictDefaults(),
            Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z"));
    }

    /// <summary>Test double mimicking FileAttestationStore integrity recompute (R5-001).</summary>
    private sealed class StoreSideVerifier
    {
        private readonly IAttestationMac _mac;
        private readonly byte[] _key;

        public StoreSideVerifier(IAttestationMac mac, byte[] key)
        {
            _mac = mac;
            _key = key;
        }

        public string RecomputeHmac(Attestation attestation) =>
            _mac.ComputeBase64(AttestationMacMaterial.CanonicalUtf8WithoutHmac(attestation), _key);

        public bool Verify(Attestation attestation) =>
            string.Equals(attestation.HmacSha256Base64, RecomputeHmac(attestation), StringComparison.Ordinal);
    }
}
