using Sav.Application.Abstractions;
using Sav.Domain.Attestations;
using Sav.Domain.Errors;

namespace Sav.Application.Attestations;

public sealed class GetAttestationUseCase : IGetAttestationUseCase
{
    private readonly IAttestationStore _store;
    private readonly IAttestationMac _mac;
    private readonly IRedactor _redactor;
    private readonly byte[] _hmacKey;

    public GetAttestationUseCase(
        IAttestationStore store,
        IAttestationMac mac,
        IRedactor redactor,
        byte[] hmacKey)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
        ArgumentNullException.ThrowIfNull(hmacKey);
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("HMAC key must be at least 32 bytes.", nameof(hmacKey));
        }

        _hmacKey = hmacKey.ToArray();
    }

    public async Task<Attestation?> ExecuteAsync(string attestationId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(attestationId);
        cancellationToken.ThrowIfCancellationRequested();

        Attestation? stored = await _store.GetAsync(attestationId, cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        if (!AttestationFactory.VerifyIntegrity(stored, _mac, _hmacKey))
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation HMAC verification failed.");
        }

        // Idempotent re-redact; signed fields must remain unchanged for verify to stay valid.
        Attestation redacted = _redactor.RedactObject(stored, stored.EffectiveDisclosure);
        if (!AttestationFactory.VerifyIntegrity(redacted, _mac, _hmacKey))
        {
            // Re-redaction mutated signed material: fail closed.
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Post-verify redaction mutated signed body.");
        }

        return redacted;
    }
}
