using System.Security.Cryptography;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Attestations;

namespace Sav.Application.Attestations;

/// <summary>
/// Builds attestations: draft → redact → HMAC via <see cref="IAttestationMac"/>.
/// Does not implement HMAC itself and does not persist.
/// </summary>
public sealed class AttestationFactory
{
    private readonly IAttestationMac _mac;
    private readonly IRedactor _redactor;

    public AttestationFactory(IAttestationMac mac, IRedactor redactor)
    {
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
    }

    public Attestation Create(AttestationDraft draft, ReadOnlySpan<byte> hmacKey)
    {
        ArgumentNullException.ThrowIfNull(draft);
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("HMAC key must be at least 32 bytes.", nameof(hmacKey));
        }

        Attestation unsigned = new(
            schemaVersion: draft.SchemaVersion,
            id: draft.Id,
            sqlHash: draft.SqlHash,
            contractHash: draft.ContractHash,
            policyHash: draft.PolicyHash,
            savVersion: draft.SavVersion,
            targetAliasFingerprint: draft.TargetAliasFingerprint,
            decision: draft.Decision,
            analysis: draft.Analysis,
            planSummary: draft.PlanSummary,
            properties: draft.Properties,
            effectiveDisclosure: draft.EffectiveDisclosure,
            timestamp: draft.Timestamp,
            hmacSha256Base64: string.Empty);

        Attestation redacted = _redactor.RedactObject(unsigned, draft.EffectiveDisclosure);

        // Keep hmac out of the MAC input even if the redactor left an empty string.
        Attestation redactedUnsigned = WithHmac(redacted, string.Empty);
        byte[] bodyUtf8 = AttestationMacMaterial.CanonicalUtf8WithoutHmac(redactedUnsigned);
        string hmac = _mac.ComputeBase64(bodyUtf8, hmacKey);
        return WithHmac(redactedUnsigned, hmac);
    }

    public static bool VerifyIntegrity(
        Attestation attestation,
        IAttestationMac mac,
        ReadOnlySpan<byte> hmacKey)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(mac);
        if (hmacKey.Length < 32)
        {
            return false;
        }

        byte[] bodyUtf8 = AttestationMacMaterial.CanonicalUtf8WithoutHmac(attestation);
        string expected = mac.ComputeBase64(bodyUtf8, hmacKey);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(attestation.HmacSha256Base64));
    }

    private static Attestation WithHmac(Attestation source, string hmac) =>
        new(
            schemaVersion: source.SchemaVersion,
            id: source.Id,
            sqlHash: source.SqlHash,
            contractHash: source.ContractHash,
            policyHash: source.PolicyHash,
            savVersion: source.SavVersion,
            targetAliasFingerprint: source.TargetAliasFingerprint,
            decision: source.Decision,
            analysis: source.Analysis,
            planSummary: source.PlanSummary,
            properties: source.Properties,
            effectiveDisclosure: source.EffectiveDisclosure,
            timestamp: source.Timestamp,
            hmacSha256Base64: hmac);
}
