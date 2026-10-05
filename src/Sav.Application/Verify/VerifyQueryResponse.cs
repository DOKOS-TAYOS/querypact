using Sav.Domain.Attestations;

namespace Sav.Application.Verify;

/// <summary>
/// Public verify_query response: attestation id + signed attestation body.
/// </summary>
public sealed record VerifyQueryResponse(
    string AttestationId,
    Attestation Attestation);
