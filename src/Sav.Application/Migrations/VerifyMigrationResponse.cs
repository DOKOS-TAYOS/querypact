using Sav.Domain.Attestations;

namespace Sav.Application.Migrations;

public sealed record VerifyMigrationResponse(
    string AttestationId,
    Attestation Attestation);
