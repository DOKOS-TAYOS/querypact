using System.Security.Cryptography;
using Sav.Application.Abstractions;

namespace Sav.Infrastructure.Storage.Attestations;

/// <summary>
/// HMAC-SHA256 + Base64 via BCL (<see cref="IAttestationMac"/>).
/// </summary>
public sealed class AttestationHmac : IAttestationMac
{
    public string ComputeBase64(ReadOnlySpan<byte> canonicalRedactedBodyUtf8, ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("HMAC key must not be empty.", nameof(key));
        }

        byte[] hash = HMACSHA256.HashData(key, canonicalRedactedBodyUtf8);
        return Convert.ToBase64String(hash);
    }
}
