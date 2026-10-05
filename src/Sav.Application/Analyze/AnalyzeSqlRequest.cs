namespace Sav.Application.Analyze;

public sealed record AnalyzeSqlRequest(
    string Sql,
    string PolicyPath,
    string? ContractPath);
