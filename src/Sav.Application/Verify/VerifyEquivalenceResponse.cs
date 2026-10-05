using Sav.Domain.Attestations;

namespace Sav.Application.Verify;

/// <summary>
/// Public verify_equivalence response: attestation id + signed attestation body.
/// </summary>
public sealed record VerifyEquivalenceResponse(
    string AttestationId,
    Attestation Attestation);
