namespace Sav.Domain.Attestations;

public sealed record AttestationAnalysis(
    StructuralSqlIr Ir,
    bool IsParsable);
