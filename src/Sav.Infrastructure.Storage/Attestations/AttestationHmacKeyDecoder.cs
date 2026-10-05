using System.Globalization;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Storage.Attestations;

/// <summary>
/// Parses <c>SAV_ATTESTATION_HMAC_KEY</c>. Accepts only <c>base64:</c> or <c>hex:</c>
/// prefixes (ASCII, case-sensitive).
/// </summary>
public static class AttestationHmacKeyDecoder
{
    public const string EnvironmentVariableName = "SAV_ATTESTATION_HMAC_KEY";

    private const string Base64Prefix = "base64:";
    private const string HexPrefix = "hex:";
    private const int MinimumKeyBytes = 32;

    /// <summary>
    /// Decodes operator key material. Throws <see cref="SavException"/> with typed codes:
    /// missing, invalid_encoding, or too_weak.
    /// </summary>
    public static byte[] Decode(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyMissing,
                $"{SavErrorCode.AttestationHmacKeyMissing}: HMAC key is missing.");
        }

        string value = rawValue.Trim();

        if (value.StartsWith(Base64Prefix, StringComparison.Ordinal))
        {
            return DecodeBase64(value.Substring(Base64Prefix.Length));
        }

        if (value.StartsWith(HexPrefix, StringComparison.Ordinal))
        {
            return DecodeHex(value.Substring(HexPrefix.Length));
        }

        throw new SavException(
            SavErrorCode.AttestationHmacKeyInvalidEncoding,
            $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Key must start with '{Base64Prefix}' or '{HexPrefix}'.");
    }

    private static byte[] DecodeBase64(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyInvalidEncoding,
                $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Empty base64 payload.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(payload.Trim());
        }
        catch (FormatException)
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyInvalidEncoding,
                $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Invalid base64 payload.");
        }

        EnsureMinimumLength(bytes);
        return bytes;
    }

    private static byte[] DecodeHex(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyInvalidEncoding,
                $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Empty hex payload.");
        }

        string hex = payload.Trim();
        if (hex.Length % 2 != 0)
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyInvalidEncoding,
                $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Hex payload length must be even.");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyInvalidEncoding,
                $"{SavErrorCode.AttestationHmacKeyInvalidEncoding}: Invalid hex payload.");
        }

        EnsureMinimumLength(bytes);
        return bytes;
    }

    private static void EnsureMinimumLength(byte[] bytes)
    {
        if (bytes.Length < MinimumKeyBytes)
        {
            throw new SavException(
                SavErrorCode.AttestationHmacKeyTooWeak,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{SavErrorCode.AttestationHmacKeyTooWeak}: Key must be at least {MinimumKeyBytes} bytes after decode."));
        }
    }
}
