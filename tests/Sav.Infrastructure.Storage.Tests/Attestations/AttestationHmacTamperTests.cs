using System.Security.Cryptography;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

public sealed class AttestationHmacTamperTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x42, 32).ToArray();

    [Fact]
    public void ComputeBase64_is_stable_for_identical_body_and_key()
    {
        IAttestationMac mac = new AttestationHmac();
        byte[] body = Encoding.UTF8.GetBytes("""{"decision":"PASS","id":"a1"}""");

        string first = mac.ComputeBase64(body, Key);
        string second = mac.ComputeBase64(body, Key);

        Assert.Equal(first, second);
        Assert.False(string.IsNullOrWhiteSpace(first));
        _ = Convert.FromBase64String(first); // valid Base64
    }

    [Fact]
    public void Bit_flip_of_body_yields_integrity_failure()
    {
        IAttestationMac mac = new AttestationHmac();
        byte[] body = Encoding.UTF8.GetBytes("""{"decision":"PASS","sqlHash":"abc"}""");
        string original = mac.ComputeBase64(body, Key);

        byte[] tampered = (byte[])body.Clone();
        tampered[0] ^= 0x01;
        string afterTamper = mac.ComputeBase64(tampered, Key);

        Assert.NotEqual(original, afterTamper);
        Assert.False(CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(original),
            Encoding.UTF8.GetBytes(afterTamper)));
    }

    [Fact]
    public void Canonical_json_body_hmac_matches_bcl_reference()
    {
        IAttestationMac mac = new AttestationHmac();
        var draft = new { decision = "DENY", schemaVersion = "1", sqlHash = CanonicalJson.Sha256Hex("SELECT 1") };
        byte[] body = CanonicalJson.Utf8Bytes(draft);

        string actual = mac.ComputeBase64(body, Key);

        using HMACSHA256 hmac = new(Key);
        string expected = Convert.ToBase64String(hmac.ComputeHash(body));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Different_keys_produce_different_macs()
    {
        IAttestationMac mac = new AttestationHmac();
        byte[] body = Encoding.UTF8.GetBytes("""{"id":"x"}""");
        byte[] otherKey = Enumerable.Repeat((byte)0x99, 32).ToArray();

        Assert.NotEqual(mac.ComputeBase64(body, Key), mac.ComputeBase64(body, otherKey));
    }
}
