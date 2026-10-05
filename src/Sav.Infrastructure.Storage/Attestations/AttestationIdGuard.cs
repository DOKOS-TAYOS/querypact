using System.Text.RegularExpressions;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Storage.Attestations;

/// <summary>
/// Allow-list for attestation ids before any filesystem access (LFI / path escape).
/// Accepts <c>^[a-zA-Z0-9_-]{1,64}$</c> or a canonical UUID (hex + hyphens).
/// </summary>
public static partial class AttestationIdGuard
{
    public static void EnsureValid(string? attestationId)
    {
        if (string.IsNullOrWhiteSpace(attestationId))
        {
            throw CreateInvalid("Id is empty.");
        }

        if (attestationId.Contains('\0', StringComparison.Ordinal))
        {
            throw CreateInvalid("Id contains a null byte.");
        }

        if (UuidPattern().IsMatch(attestationId) || SimpleIdPattern().IsMatch(attestationId))
        {
            return;
        }

        throw CreateInvalid("Id is not allow-listed.");
    }

    public static bool IsValid(string? attestationId)
    {
        try
        {
            EnsureValid(attestationId);
            return true;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.AttestationIdInvalid)
        {
            return false;
        }
    }

    private static SavException CreateInvalid(string reason) =>
        new(SavErrorCode.AttestationIdInvalid, $"{SavErrorCode.AttestationIdInvalid}: {reason}");

    [GeneratedRegex(@"^[a-zA-Z0-9_-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex SimpleIdPattern();

    [GeneratedRegex(
        @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        RegexOptions.CultureInvariant)]
    private static partial Regex UuidPattern();
}
