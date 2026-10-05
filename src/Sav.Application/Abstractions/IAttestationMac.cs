namespace Sav.Application.Abstractions;

/// <summary>
/// Operator HMAC over already-redacted attestation body bytes (canonical JSON UTF-8 excluding hmac).
/// Production implementation: Storage <c>AttestationHmac</c>.
/// </summary>
public interface IAttestationMac
{
    /// <summary>
    /// Computes HMAC-SHA256 over <paramref name="canonicalRedactedBodyUtf8"/> and returns Base64.
    /// </summary>
    string ComputeBase64(ReadOnlySpan<byte> canonicalRedactedBodyUtf8, ReadOnlySpan<byte> key);
}
