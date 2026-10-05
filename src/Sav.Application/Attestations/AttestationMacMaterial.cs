using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;

namespace Sav.Application.Attestations;

/// <summary>
/// Canonical attestation body excluding <c>hmacSha256Base64</c> (MAC input).
/// Decision is wire-form <c>PASS|FAIL|REVIEW|DENY</c>.
/// </summary>
public sealed record AttestationCanonicalBody(
    string SchemaVersion,
    string Id,
    string SqlHash,
    string ContractHash,
    string PolicyHash,
    string SavVersion,
    string TargetAliasFingerprint,
    string Decision,
    AttestationAnalysis Analysis,
    PlanSummary? PlanSummary,
    IReadOnlyList<PropertyResult> Properties,
    DisclosureProfile EffectiveDisclosure,
    DateTimeOffset Timestamp);

public static class AttestationMacMaterial
{
    public static AttestationCanonicalBody ToCanonicalBody(Attestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        return new AttestationCanonicalBody(
            SchemaVersion: attestation.SchemaVersion,
            Id: attestation.Id,
            SqlHash: attestation.SqlHash,
            ContractHash: attestation.ContractHash,
            PolicyHash: attestation.PolicyHash,
            SavVersion: attestation.SavVersion,
            TargetAliasFingerprint: attestation.TargetAliasFingerprint,
            Decision: AttestationDecisionMapper.ToWire(attestation.Decision),
            Analysis: attestation.Analysis,
            PlanSummary: attestation.PlanSummary,
            Properties: attestation.Properties,
            EffectiveDisclosure: attestation.EffectiveDisclosure,
            Timestamp: attestation.Timestamp);
    }

    public static byte[] CanonicalUtf8WithoutHmac(Attestation attestation) =>
        CanonicalJson.Utf8Bytes(ToCanonicalBody(attestation));

    public static string ComputeSqlHash(string sql) =>
        CanonicalJson.Sha256Hex(sql ?? string.Empty);

    public static string ComputeContractHash<T>(T contract) =>
        CanonicalJson.Sha256Hex(contract);

    public static string ComputePolicyHash<T>(T policy) =>
        CanonicalJson.Sha256Hex(policy);
}
