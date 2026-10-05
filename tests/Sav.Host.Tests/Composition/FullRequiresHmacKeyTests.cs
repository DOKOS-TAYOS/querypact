using Microsoft.Extensions.DependencyInjection;
using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests.Composition;

public sealed class FullRequiresHmacKeyTests
{
    [Fact]
    public void Missing_hmac_key_throws_attestation_hmac_key_missing()
    {
        ServiceCollection services = new();
        SavModeOptions options = new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = Path.GetTempPath(),
            AttestationStoreRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N")),
        };

        SavException ex = Assert.Throws<SavException>(() => services.AddSavByProfile(options, hmacKey: null));
        Assert.Equal(SavErrorCode.AttestationHmacKeyMissing, ex.Code);
    }

    [Fact]
    public void Invalid_encoding_throws_attestation_hmac_key_invalid_encoding()
    {
        SavException ex = Assert.Throws<SavException>(() => AttestationHmacKeyDecoder.Decode("not-a-prefixed-key"));
        Assert.Equal(SavErrorCode.AttestationHmacKeyInvalidEncoding, ex.Code);
    }

    [Fact]
    public void Too_short_key_throws_attestation_hmac_key_too_weak()
    {
        SavException decodeEx = Assert.Throws<SavException>(() =>
            AttestationHmacKeyDecoder.Decode("base64:" + Convert.ToBase64String(new byte[8])));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, decodeEx.Code);

        ServiceCollection services = new();
        SavModeOptions options = new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = Path.GetTempPath(),
            AttestationStoreRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N")),
        };
        SavException diEx = Assert.Throws<SavException>(() => services.AddSavFull(options, new byte[8]));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, diEx.Code);
    }
}
