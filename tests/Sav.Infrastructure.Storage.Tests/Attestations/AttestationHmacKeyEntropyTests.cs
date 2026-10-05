using Sav.Domain.Errors;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

public sealed class AttestationHmacKeyEntropyTests
{
    // 32 zero bytes.
    private const string Base64Payload32Zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private const string HexPayload32Zeros = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// Unprefixed collision: valid Base64 of ≥32 bytes AND valid hex of a different length.
    /// 64× '0' → Base64 decode = 48 bytes; hex decode = 32 bytes.
    /// </summary>
    private const string CollisionUnprefixed = HexPayload32Zeros;

    [Fact]
    public void Missing_key_throws_attestation_hmac_key_missing()
    {
        SavException ex = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode(null));
        Assert.Equal(SavErrorCode.AttestationHmacKeyMissing, ex.Code);

        SavException empty = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode(string.Empty));
        Assert.Equal(SavErrorCode.AttestationHmacKeyMissing, empty.Code);

        SavException whitespace = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode("   "));
        Assert.Equal(SavErrorCode.AttestationHmacKeyMissing, whitespace.Code);
    }

    [Fact]
    public void Unprefixed_opaque_utf8_throws_invalid_encoding()
    {
        SavException ex = Assert.Throws<SavException>(
            () => AttestationHmacKeyDecoder.Decode("this-is-an-opaque-passphrase-not-allowed-in-mvp"));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, ex.Code);
    }

    [Fact]
    public void Unprefixed_collision_fixture_throws_invalid_encoding()
    {
        byte[] asBase64 = Convert.FromBase64String(CollisionUnprefixed);
        byte[] asHex = Convert.FromHexString(CollisionUnprefixed);
        Assert.True(asBase64.Length >= 32);
        Assert.True(asHex.Length >= 32);
        Assert.NotEqual(asBase64.Length, asHex.Length);

        SavException ex = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode(CollisionUnprefixed));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, ex.Code);
    }

    [Fact]
    public void Prefixed_forms_of_collision_payload_yield_distinct_key_bytes()
    {
        byte[] fromBase64 = AttestationHmacKeyDecoder.Decode("base64:" + CollisionUnprefixed);
        byte[] fromHex = AttestationHmacKeyDecoder.Decode("hex:" + CollisionUnprefixed);

        Assert.Equal(48, fromBase64.Length);
        Assert.Equal(32, fromHex.Length);
        Assert.NotEqual(fromBase64, fromHex);
    }

    [Fact]
    public void Same_32_zero_bytes_via_base64_or_hex_prefix_match()
    {
        byte[] fromBase64 = AttestationHmacKeyDecoder.Decode("base64:" + Base64Payload32Zeros);
        byte[] fromHex = AttestationHmacKeyDecoder.Decode("hex:" + HexPayload32Zeros);
        Assert.Equal(32, fromBase64.Length);
        Assert.Equal(fromBase64, fromHex);
    }

    [Fact]
    public void Too_short_after_decode_throws_too_weak()
    {
        string shortB64 = Convert.ToBase64String(new byte[16]);
        SavException b64 = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode("base64:" + shortB64));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, b64.Code);

        SavException hex = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode("hex:00112233"));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, hex.Code);
    }

    [Fact]
    public void Valid_prefixes_are_case_sensitive()
    {
        _ = AttestationHmacKeyDecoder.Decode("base64:" + Base64Payload32Zeros);
        _ = AttestationHmacKeyDecoder.Decode("hex:" + HexPayload32Zeros);

        SavException wrongCase = Assert.Throws<SavException>(
            () => AttestationHmacKeyDecoder.Decode("Base64:" + Base64Payload32Zeros));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, wrongCase.Code);

        SavException hexWrongCase = Assert.Throws<SavException>(
            () => AttestationHmacKeyDecoder.Decode("HEX:" + HexPayload32Zeros));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, hexWrongCase.Code);
    }

    [Fact]
    public void Garbage_after_valid_prefix_throws_invalid_encoding()
    {
        SavException b64 = Assert.Throws<SavException>(
            () => AttestationHmacKeyDecoder.Decode("base64:!!!not-base64!!!"));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, b64.Code);

        SavException hex = Assert.Throws<SavException>(
            () => AttestationHmacKeyDecoder.Decode("hex:zz"));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, hex.Code);
    }
}
