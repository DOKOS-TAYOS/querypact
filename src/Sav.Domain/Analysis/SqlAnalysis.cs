namespace Sav.Domain.Analysis;

public sealed record SqlAnalysis(
    SqlIr Ir,
    bool IsParsable);
